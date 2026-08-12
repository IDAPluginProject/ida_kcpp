import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_moves
import ida_name
import ida_typeinf
import idaapi

from . import logic, ui_utils, utils


class HexraysDoubleClickHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.vu = None

    def double_click(self, vu, shift):
        self.vu = vu
        if not (vu.item and vu.item.is_citem()):
            return 0
        result = logic.find_vtable_funcptr_from_expr(vu.item.e)
        if not result:
            return 0
        class_name, offset_in_vtable = result
        return jump_to_virtual_func(class_name, offset_in_vtable)


class VirtualFunctionChooser(ui_utils.Choose):
    def __init__(self, items):
        super().__init__("Choose a Virtual function...", items, [
            ["Class", 30 | self.CHCOL_PLAIN],
            ["Function name", 40 | self.CHCOL_FNAME],
            ["Address", 20 | self.CHCOL_HEX],
        ])


def jump_to_virtual_func(ancestor_name, offset_in_vtable):
    functions_table = logic.gather_funcs_from_descendants(ancestor_name, offset_in_vtable)
    vtable_func = ida_idaapi.BADADDR
    if not functions_table:
        return 0
    elif len(functions_table) == 1:
        _, vtable_func = functions_table[0]
    else:
        prepared_data = []
        functions_set = set()
        for class_name, virtual_func in functions_table:
            functions_set.add(virtual_func)
            virtual_func_formatted = "0x%016X" % virtual_func
            func_name = ida_name.get_ea_name(virtual_func)
            func_class_name, method_name = utils.parse_mangled_method_name(func_name)
            if func_class_name:
                func_name = func_class_name + "::" + method_name
            prepared_data.append((class_name, func_name, virtual_func_formatted))
        if len(functions_set) > 1:
            vf_chooser = VirtualFunctionChooser(prepared_data)
            chosen_vf = vf_chooser.show()
            if chosen_vf:
                _, _, vtable_func_formatted = chosen_vf
                vtable_func = int(vtable_func_formatted, 16)
        else:
            (vtable_func,) = functions_set
    if vtable_func != ida_idaapi.BADADDR:
        ida_kernwin.jumpto(vtable_func)
        return 1
    return 0


class VirtualFuncsSynchronizer(ida_idp.IDB_Hooks):
    def renamed(self, ea, new_name, local_name, old_name):
        if utils.is_func_start(ea):
            if "::" in new_name:
                self.unhook()
                class_name, method_name = new_name.split("::")
                full_name = utils.generate_method_name(class_name, method_name)
                utils.set_func_name(ea, full_name)
            else:
                class_name, method_name = utils.parse_mangled_method_name(new_name)
                if class_name is None:
                    # Case only actual method name was assigned without class prefix
                    if ea not in logic.vfunc_to_vmethod:
                        return
                    vfunc_metadata = logic.VFuncMetadata(*logic.vfunc_to_vmethod[ea])
                    class_name = vfunc_metadata.impl_class
                    method_name = new_name
                    full_name = utils.generate_method_name(class_name, method_name)
                    utils.set_func_name(ea, full_name)
                self.unhook()
            logic.virtual_method_renamed(ea, class_name, method_name)
            self.hook()
    
    # TODO: use lt_udm_renamed when porting to ida9
    def local_types_changed(self, ltc, ordinal, name):
        # There are two very annoying things about local_types_changed:
        #   1. the parameters tell you very little about WHAT changed.
        #      specifically, we can't really tell in which way a struct 
        #      was edited.
        #   2. this function hooks in exactly after the change starts
        #      but before it takes place. So for example if a member is
        #      modified by the user, the old name/type will still presist
        #      if this function tries to read them.
        # So in order to overcome these restrictions, we use
        # execute_ui_requests to perform the logic of this 
        # hook only AFTER the renaming/retyping takes place.
        # ...And instead of updating the functions that match
        # only the member that was modified, we update the matching
        # functions for EVERY member.
        if ltc != ida_idp.LTC_EDITED or not name.endswith("::vmethods"):
            return
        idaapi.execute_ui_requests([lambda: self._update_vmethods(name)])
    
    def _update_vmethods(self, name):
        sptr = utils.get_struct_by_name(name)
        if not sptr:
            return
        self.unhook()
        class_name = name.split("::")[0]
        for mptr, _ in utils.iterate_struct_members(sptr):
            vtable_offset = logic.find_own_vmethods_offset_in_vtable(class_name) + mptr.soff
            generic_method_name = f"method_{vtable_offset // 8}"
            logic.virtual_method_member_renamed(class_name, mptr.soff, generic_method_name)
        for mptr, _ in utils.iterate_struct_members(sptr):
            member_name = utils.get_member_name(mptr)
            logic.virtual_method_member_renamed(class_name, mptr.soff, member_name)
            logic.virtual_method_member_prototype_changed(class_name, mptr)
        self.hook()
        
    def ti_changed(self, ea, ti_type, ti_fname):
        if not utils.is_func_start(ea):
            return
        tinfo = ida_typeinf.tinfo_t()
        tinfo.deserialize(None, ti_type, ti_fname, None)
        func_details = ida_typeinf.func_type_data_t()
        tinfo.get_func_details(func_details)
        self.unhook()
        logic.virtual_method_prototype_changed(ea, func_details)
        self.hook()


class StructsDoubleColonHooks(ida_kernwin.View_Hooks):
    """Handles double-click navigation in the Local Types view.
    
    In IDA 9, the Structures view was replaced by the Local Types view.
    This hook enables navigation from type references (e.g., OSObject::vtable)
    and vmethods members to their definitions or implementations.
    """
    def __init__(self):
        super(StructsDoubleColonHooks, self).__init__()
        self.selected_expr = None
        self.double_click_triggered = False

    def view_click(self, view, event):
        widget_type = ida_kernwin.get_widget_type(view)
        # In IDA 9, the Local Types view uses BWN_TILIST (58)
        if widget_type != ida_kernwin.BWN_TILIST:
            return
        if self.double_click_triggered:
            self.double_click_triggered = False
            return
        self.selected_expr = ui_utils.get_wrapped_word_from_viewer(view)

    def view_dblclick(self, view, event):
        widget_type = ida_kernwin.get_widget_type(view)
        # In IDA 9, the Local Types view uses BWN_TILIST (58)
        if widget_type != ida_kernwin.BWN_TILIST:
            return
        self.double_click_triggered = True
        if not self.selected_expr:
            return
        expr = self.selected_expr
        e = ida_moves.lochist_entry_t()
        if not ida_kernwin.get_custom_viewer_location(e, view):
            return
        place = e.place()
        if not place:
            return
        # In IDA 9, only tiplace_t is used (structplace_t was removed)
        tiplace = place.as_tiplace_t(place) if hasattr(place, "as_tiplace_t") else None
        if not tiplace:
            return

        if "::" in expr and " " not in expr:
            # Case click on struct type such as "OSObject::field"
            sid = utils.get_struct_tid_by_name(expr)
            if sid == ida_idaapi.BADADDR:
                return
            sidx = utils.get_struct_ordinal(sid)
            if sidx == 0:
                return
            ida_kernwin.open_loctypes_window(sidx)
            self.selected_expr = None
        else:
            # Checking for a case click on vmethod
            navigate_to_vmethod_impl(tiplace.ordinal, expr)


def navigate_to_vmethod_impl(type_ordinal, expr):
    """Navigate to virtual method implementation from Local Types view.
    
    Args:
        type_ordinal: The ordinal of the type in Local Types
        expr: The expression/word under cursor (may include * prefix)
    
    Returns:
        True if navigation succeeded, False otherwise
    """
    sptr = utils.get_struct_by_ordinal(type_ordinal)
    if not sptr:
        return False
    
    struct_name = utils.get_struct_name(sptr)
    if not struct_name or not struct_name.endswith("::vmethods"):
        return False
    
    # Strip pointer indicator from expression (e.g., "*methodName" -> "methodName")
    member_name = expr.lstrip('*')
    member = utils.get_member_by_name(sptr, member_name)
    if not member:
        return False
    
    name = utils.get_member_name(member)
    if not name or name != member_name:
        return False
    
    # Navigate to the method implementation
    class_name = "::".join(struct_name.split("::")[:-1])
    vmethod_offset_in_obj = logic.find_own_vmethods_offset_in_vtable(class_name) + member.soff
    jump_to_virtual_func(class_name, vmethod_offset_in_obj)
    return True



class JumpToVMethodHandler(ida_kernwin.action_handler_t):
    """Action handler for jumping to virtual method implementation.
    
    Provides Cmd+Enter (macOS) / Ctrl+Enter (Windows/Linux) shortcut
    in Local Types view to navigate to method implementations.
    """
    ACTION_NAME = 'kcpp:jump_to_vmethod'
    ACTION_SHORTCUT = 'Meta+Enter'
    ACTION_LABEL = 'Jump to virtual method implementation'
    ACTION_TOOLTIP = 'Navigate to the virtual method implementation (kcpp)'

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        widget = ctx.widget
        if not widget:
            return 0
        
        # Get the word under cursor
        expr = ui_utils.get_wrapped_word_from_viewer(widget)
        if not expr:
            return 0
        
        # Get current location to find the struct
        e = ida_moves.lochist_entry_t()
        if not ida_kernwin.get_custom_viewer_location(e, widget):
            return 0
        place = e.place()
        if not place:
            return 0
        
        tiplace = place.as_tiplace_t(place) if hasattr(place, 'as_tiplace_t') else None
        if not tiplace:
            return 0
        
        return 1 if navigate_to_vmethod_impl(tiplace.ordinal, expr) else 0

    def update(self, ctx):
        # Only enable in Local Types view
        if ctx.widget_type == ida_kernwin.BWN_TILIST:
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE

    @classmethod
    def register(cls):
        """Register the action with IDA."""
        action_desc = ida_kernwin.action_desc_t(
            cls.ACTION_NAME,
            cls.ACTION_LABEL,
            cls(),
            cls.ACTION_SHORTCUT,
            cls.ACTION_TOOLTIP,
            -1
        )
        return ida_kernwin.register_action(action_desc)

    @classmethod
    def unregister(cls):
        """Unregister the action from IDA."""
        return ida_kernwin.unregister_action(cls.ACTION_NAME)


def open_smart_xrefs():
    ea = ida_kernwin.get_screen_ea()
    vmethod_member_id = logic.get_member_id_for_vfunc(ea)
    if vmethod_member_id:
        ida_kernwin.open_xrefs_window(vmethod_member_id)

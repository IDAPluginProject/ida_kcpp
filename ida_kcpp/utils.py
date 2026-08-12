import logging

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_nalt
import ida_name
import ida_typeinf
import idaapi
import idc
from ida_kernelcache import symbol


class StructMember:
    def __init__(self, sptr, idx, udm):
        self._sptr = sptr
        self._idx = idx
        self._udm = udm
        self.id = sptr.get_udm_tid(idx) if idx >= 0 else ida_idaapi.BADADDR

    @property
    def soff(self):
        return self._udm.offset // 8

    def get_size(self):
        return self._udm.size // 8

    @property
    def name(self):
        return self._udm.name

    @property
    def type(self):
        return self._udm.type

    @property
    def cmt(self):
        return self._udm.cmt

    @property
    def idx(self):
        return self._idx


def _as_tinfo(sptr_or_tid):
    if isinstance(sptr_or_tid, ida_typeinf.tinfo_t):
        return sptr_or_tid
    if isinstance(sptr_or_tid, int):
        return ida_typeinf.tinfo_t(tid=sptr_or_tid)
    return None


def batch_mode(func):
    def wrapper(*args, **kwargs):
        old_batch = idc.batch(1)
        try:
            return func(*args, **kwargs)
        finally:
            idc.batch(old_batch)

    return wrapper


def generate_method_name(classname, methodname):
    # TODO: this is a temp solution to have templated classes names resolved well. Need a permanent one.
    new_class_part = symbol.global_name(classname).replace("__ZN", "").replace("__Z", "")

    # the "_99" is a marker which IDA ignores and will let us identify self-generated mangled names
    return "__ZNK{}{}{}Ev_99".format(
        new_class_part, len(methodname), methodname
    )


def parse_mangled_method_name(mangled_name):
    demangled_name = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DN))
    if not demangled_name:
        return None, None
    # Now strip arguments list such as in 'OSDictionary::setObject(OSSymbol const*, OSMetaClassBase const*)'
    strip_args = demangled_name.split("(")[0].split("::")
    method_name = strip_args[-1]
    if len(strip_args) < 2:
        return None, strip_args[0]
    class_name = "::".join(strip_args[:-1])
    if method_name[0] == '~' and method_name[1:] == class_name.split("<")[0]:
        method_name = "dtor"
    return class_name, method_name


# Functions below were copied from ida_medigate


def get_func_details(func_ea):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, func_ea)
    if not tinfo.is_func():
        return None
    func_details = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(func_details)
    return func_details


def update_func_details(func_ea, func_details):
    function_tinfo = ida_typeinf.tinfo_t()
    function_tinfo.create_func(func_details)
    if not ida_typeinf.apply_tinfo(func_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE):
        return None
    return function_tinfo


def duplicate_details_with_this(method_details, this_type):
    new_method_details = ida_typeinf.func_type_data_t()
    new_method_details.retloc = method_details.retloc
    new_method_details.rettype = method_details.rettype
    new_method_details.stkargs = method_details.stkargs
    # IDA 9: func_type_data_t.cc property replaced with get_explicit_cc()/set_cc()
    new_method_details.set_cc(method_details.get_explicit_cc())
    if len(method_details) > 0:
        old_this_arg = method_details[0]
        new_arg = ida_typeinf.funcarg_t()
        new_arg.cmt = old_this_arg.cmt
        new_arg.name = old_this_arg.name
        new_arg.flags = old_this_arg.flags
        new_arg.argloc = old_this_arg.argloc
        new_arg.type = this_type
        new_method_details.push_back(new_arg)
        for i in range(1, method_details.size()):
            new_method_details.push_back(method_details[i])
    return new_method_details


def get_struct_tid_by_name(struct_name):
    return ida_typeinf.get_named_type_tid(struct_name)


def get_struct_by_name(struct_name):
    s_id = get_struct_tid_by_name(struct_name)
    if s_id == ida_idaapi.BADADDR:
        return None
    return ida_typeinf.tinfo_t(tid=s_id)


def get_struct_name(sptr_or_tid):
    sptr = _as_tinfo(sptr_or_tid)
    if sptr is None:
        return None
    return ida_typeinf.get_tid_name(sptr.get_tid())


def get_struct_size(sptr_or_tid):
    sptr = _as_tinfo(sptr_or_tid)
    if sptr is None:
        return 0
    return sptr.get_size()


def get_struct_from_tinfo(struct_tinfo):
    if not (struct_tinfo.is_struct() or struct_tinfo.is_union()):
        return None
    tid = struct_tinfo.get_tid()
    if tid == ida_idaapi.BADADDR:
        return None
    return ida_typeinf.tinfo_t(tid=tid)


def deref_tinfo(tinfo):
    pointed_obj = None
    if tinfo.is_ptr():
        pointed_obj = tinfo.get_pointed_object()
    return pointed_obj


def deref_struct_from_tinfo(tinfo):
    struct_tinfo = deref_tinfo(tinfo)
    if struct_tinfo is None:
        return None
    return get_struct_from_tinfo(struct_tinfo)


def extract_struct_from_tinfo(tinfo):
    struct = get_struct_from_tinfo(tinfo)
    if struct is None:
        struct = deref_struct_from_tinfo(tinfo)
    return struct


def decompile_and_update_this(func_ea, this_type=None):
    functype = None
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        functype = cfunc.type
        func_details = ida_typeinf.func_type_data_t()
        functype.get_func_details(func_details)
        if func_details is None:
            return None
        if this_type:
            if len(func_details) > 0:
                func_details[0].name = "this"
                func_details[0].type = this_type
        functype = update_func_details(func_ea, func_details)
    except ida_hexrays.DecompilationFailure as e:
        logging.exception("Couldn't decompile 0x%x", func_ea)
    return functype


def get_sptr_by_name(struct_name):
    return get_struct_by_name(struct_name)


def set_func_name(func_ea, func_name):
    counter = 0
    new_name = func_name
    flags = ida_name.SN_AUTO | ida_name.SN_FORCE | ida_name.SN_NOWARN
    while not ida_name.set_name(func_ea, new_name, flags) and counter < 20:
        new_name = func_name + "_%d" % counter
        counter += 1
    return new_name


def get_member_by_offset(sptr, offset):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return None
    idx, udm = sptr.get_udm_by_offset(offset * 8)
    if idx >= 0 and udm is not None and (udm.offset // 8) == offset:
        return StructMember(sptr, idx, udm)
    return None


def get_member_by_name(sptr, name):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return None
    idx, udm = sptr.get_udm(name)
    if idx < 0 or udm is None:
        return None
    return StructMember(sptr, idx, udm)


def get_member_substruct(member):
    member_type = get_member_tinfo(member)
    if member_type is None:
        return None
    if member_type.is_struct() or member_type.is_union():
        return get_struct_from_tinfo(member_type)
    if member_type.is_ptr():
        pointed = member_type.get_pointed_object()
        if pointed and (pointed.is_struct() or pointed.is_union()):
            return get_struct_from_tinfo(pointed)
    return None


def get_member_tinfo(member, member_typeinf=None):
    if member is None:
        return None
    if member_typeinf is not None:
        ida_typeinf.copy_tinfo_t(member_typeinf, member.type)
        return member_typeinf
    return member.type


def get_typeinf(typestr):
    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(ida_typeinf.get_idati(), typestr)
    return tif


def get_typeinf_ptr(typeinf):
    old_typeinf = typeinf
    if isinstance(typeinf, str):
        typeinf = get_typeinf(typeinf)
    if typeinf is None:
        logging.warning("Couldn't find typeinf %s", old_typeinf or typeinf)
        return None
    tif = ida_typeinf.tinfo_t()
    tif.create_ptr(typeinf)
    return tif


def get_member_name(member):
    if member is None:
        return None
    return member.name


def get_member_cmt(member):
    if member is None:
        return None
    return member.cmt


def get_member_tid(member):
    if member is None:
        return ida_idaapi.BADADDR
    return member.id


def set_member_name(sptr, offset, name):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return False
    idx, _ = sptr.get_udm_by_offset(offset * 8)
    if idx < 0:
        return False
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.rename_udm(idx, name) == 0


def set_member_cmt(sptr, member, comment, repeatable):
    sptr = _as_tinfo(sptr)
    if sptr is None or member is None:
        return False
    is_regcmt = not bool(repeatable)
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.set_udm_cmt(member.idx, comment, is_regcmt) == 0


def set_member_tinfo(sptr, member, tinfo, flags=ida_typeinf.TINFO_DEFINITE):
    sptr = _as_tinfo(sptr)
    if sptr is None or member is None:
        return False
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.set_udm_type(member.idx, tinfo, flags) == 0


def iterate_struct_members(sptr):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return
    nmembers = sptr.get_udt_nmembers()
    if nmembers < 0:
        return
    for idx in range(nmembers):
        _, udm = sptr.get_udm(idx)
        if udm is None:
            continue
        yield StructMember(sptr, idx, udm), udm.offset // 8


def get_struct_first_offset(sptr):
    first = None
    for _, offset in iterate_struct_members(sptr):
        if first is None or offset < first:
            first = offset
    return first if first is not None else ida_idaapi.BADADDR


def get_struct_next_offset(sptr, offset):
    next_offset = None
    for _, off in iterate_struct_members(sptr):
        if off > offset and (next_offset is None or off < next_offset):
            next_offset = off
    return next_offset if next_offset is not None else ida_idaapi.BADADDR


def del_struct_member(sptr, offset):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return False
    idx, _ = sptr.get_udm_by_offset(offset * 8)
    if idx < 0:
        return False
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.del_udm(idx) == 0


def del_struct_members(sptr, start_offset, end_offset):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return False
    nmembers = sptr.get_udt_nmembers()
    if nmembers < 0:
        return False
    to_delete = []
    for idx in range(nmembers):
        _, udm = sptr.get_udm(idx)
        if udm is None:
            continue
        off = udm.offset // 8
        if start_offset <= off < end_offset:
            to_delete.append(idx)
    for idx in reversed(to_delete):
        sptr.del_udm(idx)
    return True


def add_struct_member(sptr, new_member_name, offset, member_type, member_size):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return False
    udm = ida_typeinf.udm_t()
    udm.offset = offset * 8
    if new_member_name:
        udm.name = new_member_name
        etf_flags = 0
    else:
        udm.name = ""
        etf_flags = ida_typeinf.ETF_AUTONAME
    if member_type is None:
        member_type = ida_typeinf.tinfo_t()
        member_type.create_simple_type(ida_typeinf.BT_INT8)
    udm.type = member_type
    udm.size = member_size * 8
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.add_udm(udm, etf_flags) == 0


def expand_struct(sptr, idx, delta):
    sptr = _as_tinfo(sptr)
    if sptr is None:
        return False
    # IDA 9: tinfo_code_t returns TERR_OK (0) on success, negative on error
    return sptr.expand_udt(idx, delta) == 0


def get_struct_ordinal(sptr_or_tid):
    sptr = _as_tinfo(sptr_or_tid)
    if sptr is None:
        return 0
    return sptr.get_ordinal()


def get_tid_by_ordinal(ordinal):
    til = ida_typeinf.get_idati()
    name = ida_typeinf.get_numbered_type_name(til, ordinal)
    if not name:
        return ida_idaapi.BADADDR
    return ida_typeinf.get_named_type_tid(name)


def get_struct_by_ordinal(ordinal):
    tid = get_tid_by_ordinal(ordinal)
    if tid == ida_idaapi.BADADDR:
        return None
    return ida_typeinf.tinfo_t(tid=tid)


def is_func_start(ea):
    func = ida_funcs.get_func(ea)
    if func:
        return func.start_ea == ea
    return False


def add_struct_substruct_member(sptr, new_member_name, offset, substruct_id):
    substruct_tinfo = ida_typeinf.tinfo_t(tid=substruct_id)
    member_size = get_struct_size(substruct_id)
    del_struct_members(sptr, offset, offset + member_size)
    return add_struct_member(sptr, new_member_name, offset, substruct_tinfo, member_size)

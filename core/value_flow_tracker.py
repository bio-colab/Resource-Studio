from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import capstone

# Win32 Resource API signatures and argument mapping
# Format: (resource_id_arg_index, resource_type_arg_index)
# 0-indexed:
# On x64: arg0=rcx, arg1=rdx, arg2=r8, arg3=r9
# On x86: arg0=top of stack, arg1=next, etc.
WIN32_RESOURCE_API_SPECS: dict[str, dict[str, Any]] = {
    "LoadStringA": {"id_arg": 1, "type": "STRING", "abi_x64_reg": "rdx"},
    "LoadStringW": {"id_arg": 1, "type": "STRING", "abi_x64_reg": "rdx"},
    "FindResourceA": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "FindResourceW": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "FindResourceExA": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "FindResourceExW": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "DialogBoxParamA": {"id_arg": 1, "type": "DIALOG", "abi_x64_reg": "rdx"},
    "DialogBoxParamW": {"id_arg": 1, "type": "DIALOG", "abi_x64_reg": "rdx"},
    "CreateDialogParamA": {"id_arg": 1, "type": "DIALOG", "abi_x64_reg": "rdx"},
    "CreateDialogParamW": {"id_arg": 1, "type": "DIALOG", "abi_x64_reg": "rdx"},
    "LoadIconA": {"id_arg": 1, "type": "GROUP_ICON", "abi_x64_reg": "rdx"},
    "LoadIconW": {"id_arg": 1, "type": "GROUP_ICON", "abi_x64_reg": "rdx"},
    "LoadCursorA": {"id_arg": 1, "type": "GROUP_CURSOR", "abi_x64_reg": "rdx"},
    "LoadCursorW": {"id_arg": 1, "type": "GROUP_CURSOR", "abi_x64_reg": "rdx"},
    "LoadImageA": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "LoadImageW": {"id_arg": 1, "type_arg": 2, "abi_x64_reg": "rdx", "abi_x64_type_reg": "r8"},
    "LoadBitmapA": {"id_arg": 1, "type": "BITMAP", "abi_x64_reg": "rdx"},
    "LoadBitmapW": {"id_arg": 1, "type": "BITMAP", "abi_x64_reg": "rdx"},
    "LoadMenuA": {"id_arg": 1, "type": "MENU", "abi_x64_reg": "rdx"},
    "LoadMenuW": {"id_arg": 1, "type": "MENU", "abi_x64_reg": "rdx"},
    "LoadAcceleratorsA": {"id_arg": 1, "type": "ACCELERATOR", "abi_x64_reg": "rdx"},
    "LoadAcceleratorsW": {"id_arg": 1, "type": "ACCELERATOR", "abi_x64_reg": "rdx"},
}

# Standard x86/x64 register aliases mapped to canonical root registers
X64_REG_CANONICAL: dict[str, str] = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10": "r10", "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11": "r11", "r11d": "r11", "r11w": "r11", "r11b": "r11",
    "r12": "r12", "r12d": "r12", "r12w": "r12", "r12b": "r12",
    "r13": "r13", "r13d": "r13", "r13w": "r13", "r13b": "r13",
    "r14": "r14", "r14d": "r14", "r14w": "r14", "r14b": "r14",
    "r15": "r15", "r15d": "r15", "r15w": "r15", "r15b": "r15",
}


@dataclass(frozen=True)
class ValueFlowBinding:
    call_address: int
    api_name: str
    target_id: int
    resource_type: str | None
    confidence: str  # "PROVEN_REGISTER_FLOW", "HEURISTIC_IMMEDIATE", "DIRECT_LEA"
    evidence_instructions: tuple[str, ...]
    register_used: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "callAddress": hex(self.call_address),
            "apiName": self.api_name,
            "targetId": self.target_id,
            "resourceType": self.resource_type,
            "confidence": self.confidence,
            "evidenceInstructions": list(self.evidence_instructions),
            "registerUsed": self.register_used,
        }


class ValueFlowTracker:
    """
    Intra-basic-block register state and value-flow tracker for x86 and x64.
    Tracks constant propagation, zeroing idioms, and LEA displacement calculations
    to resolve Win32 resource API arguments with decompiler-level confidence.
    """

    def __init__(self, is_64bit: bool = True) -> None:
        self.is_64bit = is_64bit
        self.reg_values: dict[str, int] = {}
        self.reg_history: dict[str, list[str]] = {}
        self.stack_pushes: list[tuple[int, str]] = []  # (value, insn_str) for x86 stack ABI

    def reset_block(self) -> None:
        self.reg_values.clear()
        self.reg_history.clear()
        self.stack_pushes.clear()

    def _canonical(self, reg_name: str) -> str:
        return X64_REG_CANONICAL.get(reg_name.lower(), reg_name.lower())

    def process_instruction(self, insn: Any) -> None:
        """
        Updates tracked register states and stack pushes based on instruction semantics.
        """
        mnemonic = insn.mnemonic.lower()
        op_str = insn.op_str
        insn_repr = f"{insn.mnemonic} {op_str}".strip()

        # 1. Zeroing Idioms: XOR reg, reg or SUB reg, reg
        if mnemonic in ("xor", "sub") and len(insn.operands) >= 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if (
                op0.type == capstone.x86.X86_OP_REG
                and op1.type == capstone.x86.X86_OP_REG
                and op0.reg == op1.reg
            ):
                reg_name = insn.reg_name(op0.reg)
                can_reg = self._canonical(reg_name)
                self.reg_values[can_reg] = 0
                self.reg_history[can_reg] = [insn_repr]
                return

        # 2. MOV reg, imm
        if mnemonic == "mov" and len(insn.operands) >= 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if op0.type == capstone.x86.X86_OP_REG:
                reg_name = insn.reg_name(op0.reg)
                can_reg = self._canonical(reg_name)
                if op1.type == capstone.x86.X86_OP_IMM:
                    val = op1.imm & 0xFFFFFFFF
                    self.reg_values[can_reg] = val
                    self.reg_history[can_reg] = [insn_repr]
                    return
                elif op1.type == capstone.x86.X86_OP_REG:
                    src_name = insn.reg_name(op1.reg)
                    src_can = self._canonical(src_name)
                    if src_can in self.reg_values:
                        self.reg_values[can_reg] = self.reg_values[src_can]
                        self.reg_history[can_reg] = list(self.reg_history.get(src_can, [])) + [insn_repr]
                        return
                    else:
                        self.reg_values.pop(can_reg, None)
                        self.reg_history.pop(can_reg, None)
                        return
                else:
                    self.reg_values.pop(can_reg, None)
                    self.reg_history.pop(can_reg, None)
                    return

        # 3. LEA reg, [mem] - crucial for compiler-optimized constant loads like `lea edx, [rax + 0x71]`
        if mnemonic == "lea" and len(insn.operands) >= 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if op0.type == capstone.x86.X86_OP_REG and op1.type == capstone.x86.X86_OP_MEM:
                reg_name = insn.reg_name(op0.reg)
                can_reg = self._canonical(reg_name)
                mem = op1.mem
                disp = mem.disp & 0xFFFFFFFF

                # If base is NO_REG (absolute address / displacement only)
                if mem.base == 0 and mem.index == 0:
                    self.reg_values[can_reg] = disp
                    self.reg_history[can_reg] = [insn_repr]
                    return

                # If base register is known to be 0 or known constant
                base_val = 0
                base_known = False
                if mem.base != 0:
                    base_name = insn.reg_name(mem.base)
                    base_can = self._canonical(base_name)
                    if base_can in self.reg_values:
                        base_val = self.reg_values[base_can]
                        base_known = True
                else:
                    base_known = True

                # If index register is known
                index_val = 0
                index_known = False
                if mem.index != 0:
                    idx_name = insn.reg_name(mem.index)
                    idx_can = self._canonical(idx_name)
                    if idx_can in self.reg_values:
                        index_val = self.reg_values[idx_can] * mem.scale
                        index_known = True
                else:
                    index_known = True

                if base_known and index_known:
                    calculated = (base_val + index_val + disp) & 0xFFFFFFFF
                    self.reg_values[can_reg] = calculated
                    hist = []
                    if mem.base != 0:
                        hist.extend(self.reg_history.get(self._canonical(insn.reg_name(mem.base)), []))
                    hist.append(insn_repr)
                    self.reg_history[can_reg] = hist
                    return
                else:
                    # If base register is unknown, we cannot guarantee constant value
                    self.reg_values.pop(can_reg, None)
                    self.reg_history.pop(can_reg, None)
                    return

        # 4. PUSH imm or PUSH reg (for 32-bit x86 stack ABI)
        if mnemonic == "push" and len(insn.operands) >= 1:
            op0 = insn.operands[0]
            if op0.type == capstone.x86.X86_OP_IMM:
                val = op0.imm & 0xFFFFFFFF
                self.stack_pushes.append((val, insn_repr))
            elif op0.type == capstone.x86.X86_OP_REG:
                reg_name = insn.reg_name(op0.reg)
                can_reg = self._canonical(reg_name)
                if can_reg in self.reg_values:
                    self.stack_pushes.append((self.reg_values[can_reg], insn_repr))
                else:
                    self.stack_pushes.append((-1, insn_repr))
            else:
                self.stack_pushes.append((-1, insn_repr))

        # 5. Invalidate modified registers if instruction clobbers them
        if len(insn.operands) > 0 and insn.operands[0].type == capstone.x86.X86_OP_REG:
            dest_reg = self._canonical(insn.reg_name(insn.operands[0].reg))
            if mnemonic not in ("cmp", "test"):
                # If not handled by explicit rules above, invalidate
                if mnemonic not in ("mov", "lea", "xor", "sub"):
                    self.reg_values.pop(dest_reg, None)
                    self.reg_history.pop(dest_reg, None)

    def resolve_api_call(self, api_name: str, call_address: int) -> ValueFlowBinding | None:
        """
        Attempts to resolve the resource ID argument for a call to a known Win32 resource API.
        """
        spec = WIN32_RESOURCE_API_SPECS.get(api_name)
        if not spec:
            return None

        if self.is_64bit:
            target_reg = spec.get("abi_x64_reg", "rdx")
            can_target = self._canonical(target_reg)
            if can_target in self.reg_values:
                val = self.reg_values[can_target]
                history = self.reg_history.get(can_target, [])
                return ValueFlowBinding(
                    call_address=call_address,
                    api_name=api_name,
                    target_id=val,
                    resource_type=spec.get("type"),
                    confidence="PROVEN_REGISTER_FLOW",
                    evidence_instructions=tuple(history),
                    register_used=target_reg,
                )
        else:
            # 32-bit x86: push order is right-to-left.
            # For LoadString(hInst, uID, lpBuf, cchMax):
            # pushes: cchMax, lpBuf, uID, hInst -> call
            # Top of stack (last push) is hInst (arg0), second from top is uID (arg1).
            id_arg_idx = spec.get("id_arg", 1)
            # When call occurs, pushes[-1] is arg 0, pushes[-2] is arg 1, etc.
            stack_offset = -(id_arg_idx + 1)
            if len(self.stack_pushes) >= abs(stack_offset):
                val, insn_str = self.stack_pushes[stack_offset]
                if val >= 0:
                    return ValueFlowBinding(
                        call_address=call_address,
                        api_name=api_name,
                        target_id=val,
                        resource_type=spec.get("type"),
                        confidence="PROVEN_REGISTER_FLOW",
                        evidence_instructions=(insn_str,),
                        register_used="stack",
                    )

        return None

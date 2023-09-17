// Constants for 13.0 beta 5 (22A5321d)

symbols = {
    p_ram_base:         ["0x800000000", "Physical address: RAM base"],
    p_ram_top_max:      ["0xc00000000", "Physical address: RAM top (max)"],

    v_cmdbufs_start:    ["0xffffffa00c188000", "GPU/FW address: Command buffer pool start"],
    v_cmdbufs_end:      ["0xffffffa00c1bc000", "GPU/FW address: Command buffer pool end"],
    v_bufmgrs:          ["0xffffffa0000d0000", "GPU/FW address: Buffer control array start"],
    v_cp_stats:         ["0xffffffa00c38f980", "GPU/FW address: Stats pointer for compute"],

    v_gptbat_base:      ["0xffffff800004d06b", "FW global variable: TTBAT base page number"],
    v_kpt_pfn:          ["0xffffff80000680b0", "FW global variable: FW/kernel page table base page number"],
    v_cur_cmd_state:    ["0xffffff80000744b0", "FW global variable: Current command state pointer"],
    v_stamp_states:     ["0xffffff8000074e18", "FW global variable: Stamp state array"],

    exploit_sp:         ["0xffffff80000bac70", "FW address: SP at exploit start"],
    v_lr:               ["0xffffff80000bacc8", "FW address: Stack LR slot"],
    v_x26:              ["0xffffff80000bac80", "FW address: Stack X26 slot"],
    v_x23:              ["0xffffff80000bac98", "FW address: Stack X23 slot"],
    v_x22:              ["0xffffff80000baca0", "FW address: Stack X22 slot"],
    v_x21:              ["0xffffff80000baca8", "FW address: Stack X21 slot"],

    g_epilogue:         ["0xffffff8000021ec0", "Gadget: Epilogue of microsequence processor function"],
    g_stack_pivot:      ["0xffffff8000006640", "Gadget: Stack pivot"],
    g_calltwo:          ["0xffffff8000045e24", "Gadget: Call two functions"],
    g_callone:          ["0xffffff8000045e3c", "Gadget: Call one function"],
    g_store:            ["0xffffff800003b310", "Gadget: Store"],
    g_uppl_call:        ["0xffffff8000006650", "Function: uPPL service call"],

    v_kpt0:             ["0xffffff8001fc8000", "FW address: Firmware page table 0 (RO)"],
    v_tmp_pt:           ["0xffffff80000b4000", "FW address: Free space (temporary PT)"],

    v_ttbat:            ["0xffffff8001000000", "FW address: Free address where TTBAT array is mapped"],
    v_ttb0_63:          ["0xffffff80010003f0", "FW address: TTBAT Context 64 TTB0 address"],

    v_scratch:          ["0xffffffa0000d2000", "GPU/FW address: Beginning of scratch space"],

    v_phys_base:        ["0xffffffc000000000", "FW address: Base of exploit physical memory map (stage 1)"],
    vg_phys_base:       ["0xffffffe000000000", "GPU/FW address: Base of exploit physical memory map (stage 2)"],

    //   New mappings in temporary page table
    vg_tmp_pt:          ["0xffffffc000010000", "FW address: New map: Temporary page table base"],
    vg_kpt0:            ["0xffffffc000014000", "FW address: New map: Firmware page table #0 (RW)"],
    vg_page0:           ["0xffffffc000018000", "FW address: New map: Physical page 0 (RAM start)"],
    vg_l2_pt:           ["0xffffffc00001c000", "FW address: New map: L2 Page table"],
    vg_l3_pt:           ["0xffffffc000020000", "FW address: New map: L3 Page table"],

    //   Global slots
    g_p_kpt0:           ["0xffffffa0000d2000", "Scratch: Firmware page table 0 pointer"],
    g_p_tmp_pt:         ["0xffffffa0000d2008", "Scratch: Temporary page table"],
    g_p_ram_start:      ["0xffffffa0000d2010", "Scratch: RAM start"],
    g_ram_size:         ["0xffffffa0000d2018", "Scratch: RAM size"],
    dbg_v_flags:        ["0xffffffa0000d2020", "Debug: Flags"],
    dbg_v_stampidx:     ["0xffffffa0000d2028", "Debug: Stamp index"],
    dbg_v_cmdq:         ["0xffffffa0000d2030", "Debug: Command queue"],
    dbg_v_cmdst:        ["0xffffffa0000d2038", "Debug: Command state"],
    tmp_v_cmdbuf:       ["0xffffffa0000d2040", "Scratch: Command buffer"],
    pg_stack_pivot:     ["0xffffffa0000d2048", "Pointer to g_stack_pivot"],
    ppg_stack_pivot:    ["0xffffffa0000d2050", "Pointer to pointer to g_stack_pivot"],
    pg_store:           ["0xffffffa0000d2058", "Pointer to g_store"],
    pg_epilogue:        ["0xffffffa0000d2060", "Pointer to g_epilogue"],
    pg_uppl_call:       ["0xffffffa0000d2068", "Pointer to g_uppl_call"],
    "uppl_map_args.va":  ["0xffffffa0000d2070", "uPPL Map call arg: VA"],
    "uppl_map_args.pa":  ["0xffffffa0000d2078", "uPPL Map call arg: PA"],
    "uppl_map_args.sz":  ["0xffffffa0000d2080", "uPPL Map call arg: Size"],
    "uppl_map_args.prot":["0xffffffa0000d2088", "uPPL Map call arg: Protection"],
    "uppl_map_args.unk": ["0xffffffa0000d2090", "uPPL Map call arg: Unknown"],
    "uppl_map_op.op":    ["0xffffffa0000d2098", "uPPL Map op: Operation ID"],
    "uppl_map_op.args":  ["0xffffffa0000d20a0", "uPPL Map op: Args pointer"],
    "uppl_switch_args.unk":["0xffffffa0000d20a8", "uPPL Context Switch call arg: Unknown"],
    "uppl_switch_args.ctx":["0xffffffa0000d20b0", "uPPL Context Switch call arg: Context ID"],
    "uppl_switch_op.op":   ["0xffffffa0000d20b8", "uPPL Switch op: Operation ID"],
    "uppl_switch_op.args": ["0xffffffa0000d20c0", "uPPL Switch op: Args pointer"],

    mseq_start:         ["0xffffffa0000d2500", "Microsequence start"],
    rop_start:          ["0xffffffa0000d2100", "ROP stack start"],

    g_mseq_loop:         ["0xffffff800001e98c", "Main microsequence interpreter loop"],

    mseq_reg0:          ["0xffffff80000744c0", "Microsequence register 0"],
    mseq_reg1:          ["0xffffff80000744c8", "Microsequence register 1"],

    v_demo_cmdbuf:     ["0xffffffa00c1918c0", "(Demo) Command buffer address"],
    v_demo_stampaddr:  ["0xffffffa00c3d8064", "(Demo) Stamp address"],
    v_demo_cmdqueue:   ["0xffffffa00c66acc0", "(Demo) Command queue address"],
    v_demo_cmdstate:   ["0xffffffa00c66ae78", "(Demo) Command state address"],

    p_demo_ttbat:       ["0x0000000bfffb8000", "(Demo) TTBAT physical address"],
    p_demo_kpt0:        ["0x0000000bfff78000", "(Demo) Firmware page table 0 physical address"],

    p_demo_tmp_pt:      ["0x801a38000", "(Demo) Temporary page table physical address"],
}


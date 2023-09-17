Emu = {
    init: function() {
        Emu.initialized = false;
        Emu.rop_mode = false;

        Emu.e = new uc.Unicorn(uc.ARCH_ARM64, uc.MODE_ARM);
        Emu.d = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
        var e = Emu.e;
        var d = Emu.d;

        d.option(cs.OPT_SKIPDATA, cs.OPT_ON);
        e.set_integer_type(ELF_INT_OBJECT)

        Emu.reset();

        $("#b_reset").click(Emu.reset);
        $("#b_next").click(Emu.next);
        $("#b_step").click(Emu.step);
        $("#b_rop").click(Emu.skip_to_rop);
        $("#b_mode").click(Emu.switch_mode);

        e.hook_add(uc.HOOK_CODE, function() {
            pc = e.reg_read_i64(uc.ARM64_REG_PC)
            if (Emu.skip_mseq && Emu.stepped) {
                if (pc.hex() == Emu.sym.g_mseq_loop || pc.hex() == Emu.sym.g_epilogue) {
                    Emu.e.emu_stop()
                }
            }
            if (Emu.steps == 0) {
                Emu.e.emu_stop()
            } else {
                Emu.steps--;
            }
            Emu.stepped = true;
        });

        $(function() {
            setTimeout(Emu.update_regs, 100);
            setTimeout(Emu.update_disasm, 100);
        });

        Reveal.on( 'slidechanged', function(event) {
            if (event.currentSlide.id == "demoslide") {
                Emu.update_regs();
            }
        });
    },

    reset: function() {
        Emu.init_symbols();
        Emu.init_exploit();
        Emu.load();
        Emu.init_mseq();
        Emu.update_mode();
        Emu.update_regs();
        Emu.update_disasm();
    },

    switch_mode: function() {
        Emu.rop_mode = !Emu.rop_mode;
        Emu.update_mode();
    },

    update_mode: function() {
        if (Emu.rop_mode) {
            console.log("ROP mode");
            $("#demo").addClass("rop-mode");
            $("#demo").removeClass("mseq-mode");
            Emu.update_disasm();
        } else {
            console.log("MSEQ mode");
            $("#demo").addClass("mseq-mode");
            $("#demo").removeClass("rop-mode");
        }
    },

    load: function() {
        var e = Emu.e;
        load_image(function(addr, b64) {
            var addr64 = new ElfUInt64(addr).or(new ElfUInt64("0xffffff0000000000"));
            var data = new Uint8Array(atob(b64).split("").map(function(c) {
                return c.charCodeAt(0);
            }));
            if (!Emu.initialized) {
                e.mem_map(addr64, data.length, uc.PROT_ALL);
            }
            e.mem_write(addr64, data)
        })

        var ret = [0xc0, 0x03, 0x5f, 0xd6];
        var nop = [0x1f, 0x20, 0x03, 0xd5];

        // Patch out send_ktrace since it uses LSE atomics
        e.mem_write("0xffffff8000023764", ret)
        // Patch out ThLock/ThUnlock since they use LSE atomics
        e.mem_write("0xffffff800003cbe0", ret)
        e.mem_write("0xffffff800003c928", ret)
        // NOP Other LSE stuff
        e.mem_write("0xffffff8000020b34", nop)
        e.mem_write("0xffffff80000258e8", nop)

        if (!Emu.initialized) {
            // Dummy map for GPU MMIO
            e.mem_map("0xffffffa010030000", 0x50000, uc.PROT_ALL);
            // Dummy map for GXF TTBAT
            e.mem_map("0xffffff8001000000", 0x4000, uc.PROT_ALL);
            // Dummy map for kpt0 phys
            e.mem_map("0xbfff78000", 0x4000, uc.PROT_ALL);
        }

        // 0xffffff8000006650 = gxf_enter

        Emu.initialized = true;
    },

    init_exploit: function() {
        Emu.linemap = {};

        var line = 0;
        var cont = $("#exploit");

        exploit_code.split("\n").forEach(function (text) {
            if (text.startsWith("%% ")) {
                var addr = text.substring(3);
                Emu.linemap[addr] = line;
                return;
            }
            var el = $(`<span class="line" id="line${line}"></span>`);
            el.text(text);
            cont.append(el);
            cont.append("\n");
            line += 1;
        });

    },

    init_symbols: function() {
        Emu.symbols = [];
        Emu.sym = {}

        Object.entries(symbols).forEach(entry => {
            var [sym, value] = entry;
            var [addr, text] = value;
            addr = new ElfUInt64(addr);
            Emu.symbols.push({
                addr: addr,
                name: sym,
                text: text,
            });
            Emu.sym[sym] = addr.hex();
        });
    },

    find_symbol: function(v) {
        if (v.and("0xfffffffff0000000").hex() != "0x0000000000000000") {
            var closest = undefined;
            Emu.symbols.forEach(function(sym) {
                if (sym.addr.hex() <= v.hex()) {
                    var delta = v.sub(sym.addr);
                    if (delta.and("0xffffff0000000000").hex() != "0x0000000000000000") {
                        return;
                    }
                    delta = delta.num();
                    if (closest === undefined || closest[1] > delta) {
                        closest = [sym, delta];
                    }
                }
            });
            return closest;
        }
        return undefined;
    },

    set_tooltip: function(e, title) {
        e.find("span.tooltiptext").remove();
        e.removeClass("tooltip");
        if (title != "") {
            e.append($("<span class='tooltiptext'>").text(title));
            e.addClass("tooltip");
        }
    },

    upval: function(e, v) {
        e.find("span.tooltiptext").remove();
        var prev = e.text();
        var cur = v.hex();
        var title = "";

        var closest = Emu.find_symbol(v);
        if (closest !== undefined && closest[1] < 0x1000) {
            var [sym, delta] = closest;
            title = cur + " " + sym.text;
            if (delta == 0) {
                cur = sym.name;
            } else {
                cur = `${sym.name} + 0x${delta.toString(16)}`;
            }
            e.addClass("symbol");
        } else {
            e.removeClass("symbol");
        }

        if (cur != prev) {
            e.addClass("changed");
        }

        e.text(cur);
        Emu.set_tooltip(e, title);
    },

    read64: function(addr) {
        var e = Emu.e;
        var val = e.mem_read(addr, 8);

        return new ElfUInt64([
            val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24),
            val[4] | (val[5] << 8) | (val[6] << 16) | (val[7] << 24),
        ]);
    },

    scrollTo: function (ele, container) {
        const eleTop = ele.offsetTop;
        const eleBottom = eleTop + ele.clientHeight;

        const containerTop = container.scrollTop;
        const containerBottom = containerTop + container.clientHeight;

        container.scrollTop = eleTop - container.clientHeight / 2;
    },

    update_regs: function() {
        var e = Emu.e;

        var sp = e.reg_read_i64(uc.ARM64_REG_SP);
        var pc = e.reg_read_i64(uc.ARM64_REG_PC);
        var r26 = e.reg_read_i64(uc.ARM64_REG_X26);

        if (Emu.prev_pc != pc) {
            $("#registers .changed").removeClass("changed");
        }
        Emu.prev_pc = pc;

        for (var i = 0; i < 30; i++) {
            Emu.upval($(`#rx${i}`), e.reg_read_i64(uc.ARM64_REG_X0 + i));
        }
        Emu.upval($("#rx30"), e.reg_read_i64(uc.ARM64_REG_X30));
        Emu.upval($("#rsp"), e.reg_read_i64(uc.ARM64_REG_SP));
        Emu.upval($("#rpc"), e.reg_read_i64(uc.ARM64_REG_PC));

        // Microsequence interpreter loop
        if (pc.hex() == Emu.sym.g_mseq_loop) {
            console.log(`MSEQ: ${r26.hex()}`)
            var line = Emu.linemap[r26.hex()];
            $("#exploit .line.current").removeClass("current");
            if (line !== undefined) {
                var el = $(`#line${line}`)
                el.addClass("current");
                el = el.get(0);
                if (el !== undefined) {
                    Emu.scrollTo(el, $("#exploit").get(0));
                }
            }

            $("#mseqregs .changed").removeClass("changed");
            Emu.upval($("#mseq0"), Emu.read64(Emu.sym.mseq_reg0));
            Emu.upval($("#mseq1"), Emu.read64(Emu.sym.mseq_reg1));
        } else if (sp.hex() >= Emu.sym.rop_start) {
            console.log(`ROP: ${sp.hex()}`)
            var line = Emu.linemap[sp.hex()];
            $("#exploit .line.current").removeClass("current");
            if (line !== undefined) {
                var el = $(`#line${line}`)
                el.addClass("current");
                el = el.get(0);
                if (el !== undefined) {
                    Emu.scrollTo(el, $("#exploit").get(0));
                }
            }
        }
    },

    update_disasm: function() {
        var e = Emu.e;
        var d = Emu.d;
        var pc = e.reg_read_i64(uc.ARM64_REG_PC);

        var context = 20;
        var start = pc.sub(context * 4);
        var count = (context * 2 + 1) * 4;

        var left = count;
        var buffer = e.mem_read(start, count);

        var instructions = d.disasm(buffer, start);

        var cont = $("#asm");
        var current = undefined;
        cont.empty();

        function process_instr(instr) {
            var addr = new ElfUInt64(instr.address);
            var title = "";
            var closest = Emu.find_symbol(addr);
            if (closest !== undefined && closest[1] == 0) {
                var [sym, delta] = closest;
                title = addr.hex() + " " + sym.text;
                var el = $("<div class='line'>\n</div>");
                var lb = $("<span class='label'></span>").text(sym.name + ":");
                el.append(lb);
                Emu.set_tooltip(lb, title);
                cont.append(el);
            }
            var op_str = instr.op_str.replace(/\bx30\b/, "lr");
            if (op_str.startsWith("#")) {
                var v = op_str.substring(1);
                var closest = Emu.find_symbol(addr);
                if (closest !== undefined && closest[1] == 0) {
                    op_str = closest[0].name;
                }
            }

            var el = $("<span class='line'></span>");
            var mn = $("<span class='op'></span>").text(instr.mnemonic.padEnd(8, ' '));
            var arg = $("<span class='args'></span>").text(op_str);
            el.text("  ");
            el.append(mn);
            el.append(arg);
            if (addr.hex() == pc.hex()) {
                el.addClass("current");
                current = el;
            }
            cont.append(el);
            cont.append("\n");
        }

        instructions.forEach(function (instr) {
            var addr = new ElfUInt64(instr.address);
            process_instr(instr);
        });

        if (current !== undefined) {
            el = current.get(0);
            if (el !== undefined) {
                Emu.scrollTo(el, $("#asm").get(0));
            }
        }
    },

    init_mseq: function() {
        var e = Emu.e;

        e.reg_write_i64(uc.ARM64_REG_X0,  "0xffffffa00c66ae78");
        e.reg_write_i64(uc.ARM64_REG_X1,  "0xffffff80000263c8");
        e.reg_write_i64(uc.ARM64_REG_X2,  "0x0000000000000003");
        e.reg_write_i64(uc.ARM64_REG_X3,  "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X4,  "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X5,  "0x000000000000000b");
        e.reg_write_i64(uc.ARM64_REG_X6,  "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X7,  "0xffffffa00c1911e1");
        e.reg_write_i64(uc.ARM64_REG_X8,  "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X9,  "0x0000000000000010");
        e.reg_write_i64(uc.ARM64_REG_X10, "0xffffff800001eee4");
        e.reg_write_i64(uc.ARM64_REG_X11, "0x0000000000000544");
        e.reg_write_i64(uc.ARM64_REG_X12, "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X13, "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X14, "0xffffff80000746b0");
        e.reg_write_i64(uc.ARM64_REG_X15, "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X16, "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X17, "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X18, "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X19, "0x0000000000000000");
        e.reg_write_i64(uc.ARM64_REG_X20, "0xffffffa00c388000");
        e.reg_write_i64(uc.ARM64_REG_X21, "0x0000000000000002");
        e.reg_write_i64(uc.ARM64_REG_X22, "0xffffff80000c2000");
        e.reg_write_i64(uc.ARM64_REG_X23, "0xffffff80000c2000");
        e.reg_write_i64(uc.ARM64_REG_X24, "0xffffff80000744a8");
        e.reg_write_i64(uc.ARM64_REG_X25, "0x0000000000000011");
        e.reg_write_i64(uc.ARM64_REG_X26, "0xffffffa0000d2500");
        e.reg_write_i64(uc.ARM64_REG_X27, "0xffffff8000021fb0");
        e.reg_write_i64(uc.ARM64_REG_X28, "0x0000000000011000");
        e.reg_write_i64(uc.ARM64_REG_X29, "0xffffff80000bacc0");
        e.reg_write_i64(uc.ARM64_REG_X30, "0xffffff800001e61c");
        e.reg_write_i64(uc.ARM64_REG_PC,  "0xffffff800001e98c");
        e.reg_write_i64(uc.ARM64_REG_SP,  "0xffffff80000baab0");
        e.reg_write_i64(uc.ARM64_REG_CPACR_EL1, "0x300000");
    },

    do_step: function() {
        var e = Emu.e;

        pc = e.reg_read_i64(uc.ARM64_REG_PC)

        if (pc.hex() == Emu.sym.g_uppl_call) {
            alert("uPPL call!");
            console.log("uPPL call!");
            pc = pc.add(4);
            e.reg_write_i64(uc.ARM64_REG_PC, pc);
        }

        Emu.stepped = false;

        if (Emu.skip_mseq) {
            Emu.steps = 32;
        } else {
            Emu.steps = 1;
        }

        e.emu_start(pc)

        Emu.update_regs();

        if (Emu.rop_mode) {
            Emu.update_disasm();
        }
    },

    do_next: function() {
        var e = Emu.e;

        Emu.do_step();

        pc = e.reg_read_i64(uc.ARM64_REG_PC)
        if (pc.hex() == Emu.sym.g_uppl_call) {
            console.log("uPPL call!");
        } else if (pc.hex() == Emu.sym.g_epilogue) {
            console.log("Epilogue!");
        } else if (pc.hex() == Emu.sym.g_mseq_loop && !Emu.skip_mseq) {
            console.log("MSEQ!");
        } else {
            setTimeout(Emu.do_next, 0);
            return;
        }
        Emu.skip_mseq = false;
    },

    next: function() {
        Emu.skip_mseq = false;
        Emu.do_next();
    },

    step: function() {
        Emu.skip_mseq = false;
        Emu.do_step();
    },

    skip_to_rop: function() {
        Emu.skip_mseq = true;
        Emu.do_next();
    },
}



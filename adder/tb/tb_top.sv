`timescale 1ns/1ns
`include "uvm_macros.svh"
import uvm_pkg::*;

// ==================== Transaction ====================
class adder_transaction extends uvm_sequence_item;
    rand logic [31:0] a;
    rand logic [31:0] b;
    rand logic        cin;

    `uvm_object_utils_begin(adder_transaction)
    `uvm_field_int(a, UVM_DEFAULT)
    `uvm_field_int(b, UVM_DEFAULT)
    `uvm_field_int(cin, UVM_DEFAULT)
    `uvm_object_utils_end

    function new(string name = "adder_transaction");
        super.new(name);
    endfunction
endclass

// ==================== Sequences ====================
class adder_base_seq extends uvm_sequence#(adder_transaction);
    `uvm_object_utils(adder_base_seq)

    function new(string name = "adder_base_seq");
        super.new(name);
    endfunction

    task body;
        adder_transaction tr;
        for (int i = 0; i < 10; i++) begin
            tr = adder_transaction::type_id::create("tr");
            start_item(tr);
            assert(tr.randomize());
            finish_item(tr);
        end
    endtask
endclass

class adder_random_seq extends uvm_sequence#(adder_transaction);
    `uvm_object_utils(adder_random_seq)

    function new(string name = "adder_random_seq");
        super.new(name);
    endfunction

    task body;
        adder_transaction tr;
        repeat(50) begin
            tr = adder_transaction::type_id::create("tr");
            start_item(tr);
            assert(tr.randomize() with { a < 1000; b < 1000; });
            finish_item(tr);
            `uvm_info("SEQ", $sformatf("a=%0d, b=%0d, cin=%0d", tr.a, tr.b, tr.cin), UVM_LOW)
        end
    endtask
endclass

// ==================== Driver ====================
class adder_driver extends uvm_driver#(adder_transaction);
    `uvm_component_utils(adder_driver)

    virtual adder_if vif;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        if (!uvm_config_db#(virtual adder_if)::get(this, "", "vif", vif))
            `uvm_fatal("DRV", "Virtual interface not found")
    endfunction

    task run_phase(uvm_phase phase);
        forever begin
            seq_item_port.get_next_item(req);
            @(posedge vif.clk);
            vif.a   <= req.a;
            vif.b   <= req.b;
            vif.cin <= req.cin;
            `uvm_info("DRV", $sformatf("Drove: a=%0d, b=%0d, cin=%0d", req.a, req.b, req.cin), UVM_LOW)
            seq_item_port.item_done();
        end
    endtask
endclass

// ==================== Monitor ====================
class adder_monitor extends uvm_monitor;
    `uvm_component_utils(adder_monitor)

    uvm_analysis_port#(adder_transaction) ap;
    virtual adder_if vif;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        ap = new("ap", this);
        if (!uvm_config_db#(virtual adder_if)::get(this, "", "vif", vif))
            `uvm_fatal("MON", "Virtual interface not found")
    endfunction

    task run_phase(uvm_phase phase);
        adder_transaction tr;
        forever begin
            @(posedge vif.clk);
            tr = adder_transaction::type_id::create("tr");
            tr.a   = vif.a;
            tr.b   = vif.b;
            tr.cin = vif.cin;
            ap.write(tr);
            `uvm_info("MON", $sformatf("Mon: a=%0d, b=%0d, cin=%0d, sum=%0d, cout=%0d",
                                        vif.a, vif.b, vif.cin, vif.sum, vif.cout), UVM_LOW)
        end
    endtask
endclass

// ==================== Scoreboard ====================
class adder_scoreboard extends uvm_scoreboard;
    `uvm_component_utils(adder_scoreboard)

    uvm_analysis_export#(adder_transaction) mon_export;
    int error_count;
    int pass_count;

    function new(string name, uvm_component parent);
        super.new(name, parent);
        error_count = 0;
        pass_count  = 0;
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        mon_export = new("mon_export", this);
    endfunction

    function void write(adder_transaction tr);
        logic [32:0] expected;
        logic [31:0] expected_sum;
        logic        expected_cout;

        expected = tr.a + tr.b + tr.cin;
        expected_sum  = expected[31:0];
        expected_cout = expected[32];

        if (vif.sum !== expected_sum || vif.cout !== expected_cout) begin
            `uvm_error("SCB", $sformatf("MISMATCH! a=%0d, b=%0d, cin=%0d => expected sum=%0d, cout=%0d | actual sum=%0d, cout=%0d",
                                        tr.a, tr.b, tr.cin, expected_sum, expected_cout, vif.sum, vif.cout))
            error_count++;
        end else begin
            `uvm_info("SCB", $sformatf("PASS: a=%0d + b=%0d + cin=%0d = sum=%0d, cout=%0d",
                                        tr.a, tr.b, tr.cin, expected_sum, expected_cout), UVM_LOW)
            pass_count++;
        end
    endfunction

    function void report_phase(uvm_phase phase);
        super.report_phase(phase);
        `uvm_info("REPORT", $sformatf("Scoreboard: %0d passed, %0d failed", pass_count, error_count), UVM_LOW)
    endfunction
endclass

// ==================== Agent ====================
class adder_agent extends uvm_agent;
    `uvm_component_utils(adder_agent)

    adder_driver    drv;
    adder_monitor   mon;
    uvm_sequencer#(adder_transaction) seqr;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        drv  = adder_driver::type_id::create("drv", this);
        mon  = adder_monitor::type_id::create("mon", this);
        seqr = uvm_sequencer#(adder_transaction)::type_id::create("seqr", this);
    endfunction

    function void connect_phase(uvm_phase phase);
        super.connect_phase(phase);
        drv.seq_item_port.connect(seqr.seq_item_export);
    endfunction
endclass

// ==================== Environment ====================
class adder_env extends uvm_env;
    `uvm_component_utils(adder_env)

    adder_agent     agent;
    adder_scoreboard scb;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        agent = adder_agent::type_id::create("agent", this);
        scb   = adder_scoreboard::type_id::create("scb", this);
    endfunction

    function void connect_phase(uvm_phase phase);
        super.connect_phase(phase);
        agent.mon.ap.connect(scb.mon_export);
    endfunction
endclass

// ==================== Test ====================
class adder_test extends uvm_test;
    `uvm_component_utils(adder_test)

    adder_env       env;
    adder_random_seq seq;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        env = adder_env::type_id::create("env", this);
        seq = adder_random_seq::type_id::create("seq");
    endfunction

    task run_phase(uvm_phase phase);
        phase.raise_objection(this);
        fork
            seq.start(env.agent.seqr);
        join_none
        #5000;
        phase.drop_objection(this);
    endfunction

    function void report_phase(uvm_phase phase);
        super.report_phase(phase);
        `uvm_info("TEST_REPORT", "Adder UVM test completed", UVM_LOW)
    endfunction
endclass

// ==================== Interface ====================
interface adder_if;
    logic        clk;
    logic [31:0] a;
    logic [31:0] b;
    logic        cin;
    logic [31:0] sum;
    logic        cout;
endinterface

// ==================== Top ====================
module top;
    logic clk = 0;

    adder_if vif();
    assign vif.clk = clk;

    // Clock generation
    initial begin
        forever #5 clk = ~clk;
    end

    // DUT instance
    adder dut (
        .a   (vif.a),
        .b   (vif.b),
        .cin (vif.cin),
        .sum (vif.sum),
        .cout(vif.cout)
    );

    initial begin
        // Set up FSDB dump
        $fsdbDumpfile("adder.fsdb");
        $fsdbDumpvars(0, top);
        $fsdbDumpvars(0, top.dut);

        // Set up interface
        uvm_config_db#(virtual adder_if)::set(null, "uvm_test_top.env.agent.drv", "vif", vif);
        uvm_config_db#(virtual adder_if)::set(null, "uvm_test_top.env.agent.mon", "vif", vif);

        run_test();
    end
endmodule

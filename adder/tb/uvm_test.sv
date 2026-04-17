`timescale 1ns/1ns
`include "uvm_macros.svh"
import uvm_pkg::*;

// Transaction
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

// Driver
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
            seq_item_port.item_done();
        end
    endtask
endclass

// Monitor
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
        end
    endtask
endclass

// Scoreboard
class adder_scoreboard extends uvm_scoreboard;
    `uvm_component_utils(adder_scoreboard)

    uvm_analysis_export#(adder_transaction) mon_export;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        mon_export = new("mon_export", this);
    endfunction

    function void write(adder_transaction tr);
        logic [31:0] expected_sum;
        logic expected_cout;
        logic [32:0] temp;

        temp = tr.a + tr.b + tr.cin;
        expected_sum  = temp[31:0];
        expected_cout = temp[32];

        `uvm_info("SCB", $sformatf("a=%0d, b=%0d, cin=%0d | expected: sum=%0d, cout=%0d | actual: sum=%0d, cout=%0d",
                                    tr.a, tr.b, tr.cin, expected_sum, expected_cout, tr.a + tr.b + tr.cin, expected_cout), UVM_LOW)

        if (expected_sum !== (tr.a + tr.b + tr.cin)) begin
            `uvm_error("SCB", "Sum mismatch!")
        end
    endfunction
endclass

// Agent
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
        mon.ap.connect(seqr_analysis_export); // simplified
    endfunction
endclass

// Environment
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

// Test
class adder_test extends uvm_test;
    `uvm_component_utils(adder_test)

    adder_env env;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction

    function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        env = adder_env::type_id::create("env", this);
    endfunction

    task run_phase(uvm_phase phase);
        phase.raise_objection(this);
        #1000;
        phase.drop_objection(this);
    endtask
endclass

// Interface
interface adder_if;
    logic clk;
    logic [31:0] a;
    logic [31:0] b;
    logic        cin;
    logic [31:0] sum;
    logic        cout;
endinterface

// Top module
module top;
    reg clk;

    adder_if vif();

    adder dut (
        .a   (vif.a),
        .b   (vif.b),
        .cin (vif.cin),
        .sum (vif.sum),
        .cout(vif.cout)
    );

    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        uvm_config_db#(virtual adder_if)::set(null, "uvm_test_top.env.agent.drv", "vif", vif);
        uvm_config_db#(virtual adder_if)::set(null, "uvm_test_top.env.agent.mon", "vif", vif);
        run_test();
    end
endmodule

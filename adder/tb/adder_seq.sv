`timescale 1ns/1ns
`include "uvm_macros.svh"
import uvm_pkg::*;

// Simplified test with sequence
class adder_base_seq extends uvm_sequence#(adder_transaction);
    `uvm_object_utils(adder_base_seq)

    function new(string name = "adder_base_seq");
        super.new(name);
    endfunction

    task body;
        adder_transaction tr;
        repeat(10) begin
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
        repeat(100) begin
            tr = adder_transaction::type_id::create("tr");
            start_item(tr);
            assert(tr.randomize() with {
                a inside {[0:100]};
                b inside {[0:100]};
            });
            finish_item(tr);
            `uvm_info("SEQ", $sformatf("Sent transaction: a=%0d, b=%0d, cin=%0d", tr.a, tr.b, tr.cin), UVM_LOW)
        end
    endtask
endclass

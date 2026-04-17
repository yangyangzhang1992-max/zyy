# Makefile for 32-bit adder UVM verification
# Usage: make comp  # compile
#        make run   # compile and run
#        make debug # run with Verdi

UVM_HOME ?= /opt/synopsys/vcs_2016/vcs-mx/L-2016.06/etc/uvm-1.2
VCS_HOME ?= /opt/synopsys/vcs_2016/vcs-mx/L-2016.06

SRC_RTL = rtl/adder.sv
SRC_TB  = tb/tb_top.sv

all: run

comp:
	@echo "=== Compiling with VCS ==="
	$(VCS_HOME)/bin/vcs \
		-fsdb \
		+incdir+$(UVM_HOME)/src \
		+acc \
		-timescale=1ns/1ns \
		-sverilog \
		$(SRC_RTL) \
		$(SRC_TB) \
		-o simv \
		-l comp.log 2>&1

run: comp
	@echo "=== Running Simulation ==="
	./simv +fsdb+final -l sim.log 2>&1

debug: comp
	@echo "=== Running with Verdi ==="
	./simv -gui=verdi +fsdb+final &

clean:
	rm -rf simv simv.daidir *.log *.fsdb *.conf work ucli.key

dve:
	@echo "=== Running with DVE ==="
	./simv -gui dve &

.PHONY: all comp run debug clean dve

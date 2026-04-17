// 32-bit adder
module adder (
    input  logic [31:0] a,
    input  logic [31:0] b,
    input  logic        cin,
    output logic [31:0] sum,
    output logic        cout
);
    logic [32:0] temp;

    assign temp = a + b + cin;
    assign sum  = temp[31:0];
    assign cout = temp[32];

endmodule

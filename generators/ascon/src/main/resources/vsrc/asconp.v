`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 05/23/2023 10:18:55 AM
// Design Name: 
// Module Name: asconp
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module asconp
    #(                  parameter                   STATE_WORDS     = 64,
                        parameter                   BYTE_WIDTH      = 8,
                        parameter   [3:0]           ROUND_16        = 4'hF,   
                        parameter   [3:0]           ROUND_12        = 4'hC   
    )
    (
                        //input       [319:0]         state_in,
                        input       [3:0]           rcon,
                        //output      [319:0]         state_out,
                        output wire      [63:0]          x0_out,    
                        output wire      [63:0]          x1_out,    
                        output wire      [63:0]          x2_out,    
                        output wire      [63:0]          x3_out,    
                        output wire      [63:0]          x4_out,    
                        input wire       [63:0]          x0_in,    
                        input wire       [63:0]          x1_in,    
                        input wire       [63:0]          x2_in,    
                        input wire       [63:0]          x3_in,    
                        input wire      [63:0]          x4_in    
    );
    
//wire [STATE_WORDS - 1:0] x0, x1, x2, x3, x4;
wire [STATE_WORDS - 1:0] x0_r, x1_r, x2_r, x3_r, x4_r;
wire [STATE_WORDS - 1:0] t0, t1;
wire [STATE_WORDS - 1:0] x0_first, x1_first, x2_first, x3_first, x4_first;
wire [STATE_WORDS - 1:0] x0_second, x1_second, x2_second, x3_second, x4_second;
wire [STATE_WORDS - 1:0] x0_third, x1_third, x2_third, x3_third, x4_third;
//wire [STATE_WORDS - 1:0] x0_rotated, x1_rotated, x2_rotated, x3_rotated, x4_rotated;
//wire [STATE_WORDS - 1:0] x0_out, x1_out, x2_out, x3_out, x4_out;
wire [BYTE_WIDTH - 1:0] round_constant;
wire [BYTE_WIDTH - 1:0] x2_constant;
wire [55: 0] x2_no_constant;
wire [3:0]               t2;

assign x0_r = x0_in;
assign x1_r = x1_in;
assign x2_r = x2_in;
assign x3_r = x3_in;
assign x4_r = x4_in;
//Linear operation and addition of round constant

assign x0_first = x0_r ^ x4_r;

assign x1_first = x1_r;

assign t2 = ROUND_12 - rcon;
assign round_constant [7:4] = ROUND_16 - t2;
assign round_constant [3:0] = t2;
assign x2_constant = x2_r[7:0] ^ x1_r[7:0] ^ round_constant;
assign x2_no_constant  = x2_r[63:8] ^ x1_r[63:8];
assign x2_first = {x2_no_constant, x2_constant};

assign x3_first = x3_r;

assign x4_first = x4_r ^ x3_r;

//Nonlinear operation
assign t0 = x0_first;
assign t1 = x1_first;
assign x0_second = x0_first ^ ((~x1_first) & x2_first);
assign x1_second = x1_first ^ ((~x2_first) & x3_first);
assign x2_second = x2_first ^ ((~x3_first) & x4_first);
assign x3_second = x3_first ^ ((~x4_first) & x0_first);
assign x4_second = x4_first ^ ((~t0) & t1);

//Linear operation
assign x0_third = x0_second ^ x4_second;
assign x1_third = x1_second ^ x0_second;
assign x2_third = ~x2_second;
assign x3_third = x2_second ^ x3_second;
assign x4_third = x4_second;

//Lane rotation
/*
assign x0_rotated = x0_third ^ {x0_third[18:0], x0_third[63:19]} ^ {x0_third[27:0], x0_third[63:28]}; 
assign x1_rotated = x1_third ^ {x1_third[60:0], x1_third[63:61]} ^ {x1_third[38:0], x1_third[63:39]}; 
assign x2_rotated = x2_third ^ {x2_third[0:0],  x2_third[63:1]}  ^ {x2_third[5:0],  x2_third[63:6]}; 
assign x3_rotated = x3_third ^ {x3_third[9:0],  x3_third[63:10]} ^ {x3_third[16:0], x3_third[63:17]}; 
assign x4_rotated = x4_third ^ {x4_third[6:0],  x4_third[63:7]}  ^ {x4_third[40:0], x4_third[63:41]}; 
*/

assign x0_out = x0_third ^ {x0_third[18:0], x0_third[63:19]} ^ {x0_third[27:0], x0_third[63:28]}; 
assign x1_out = x1_third ^ {x1_third[60:0], x1_third[63:61]} ^ {x1_third[38:0], x1_third[63:39]}; 
assign x2_out = x2_third ^ {x2_third[0:0],  x2_third[63:1]}  ^ {x2_third[5:0],  x2_third[63:6]}; 
assign x3_out = x3_third ^ {x3_third[9:0],  x3_third[63:10]} ^ {x3_third[16:0], x3_third[63:17]}; 
assign x4_out = x4_third ^ {x4_third[6:0],  x4_third[63:7]}  ^ {x4_third[40:0], x4_third[63:41]}; 

//Map 5 x 64-bit lanes to 320 bit vector output

//assign state_out [STATE_WORDS -1 + 4 * STATE_WORDS : 4 * STATE_WORDS] = x0_out;
//assign state_out [STATE_WORDS -1 + 3 * STATE_WORDS : 3 * STATE_WORDS] = x1_out;
//assign state_out [STATE_WORDS -1 + 2 * STATE_WORDS : 2 * STATE_WORDS] = x2_out;
//assign state_out [STATE_WORDS -1 + 1 * STATE_WORDS : 1 * STATE_WORDS] = x3_out;
//assign state_out [STATE_WORDS -1 + 0 * STATE_WORDS : 0 * STATE_WORDS] = x4_out;


endmodule

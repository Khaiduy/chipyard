

`timescale 1ns / 1ps


module S16 (clk, in, out);
    input clk;
    input [127:0] in;
    output [127:0] out;

    S
        S_0 (clk, in[127:120], out[127:120]),
        S_1 (clk, in[119:112], out[119:112]),
        S_2 (clk, in[111:104], out[111:104]),
        S_3 (clk, in[103:96],  out[103:96]),
        S_4 (clk, in[95:88], out[95:88]),
        S_5 (clk, in[87:80], out[87:80]),
        S_6 (clk, in[79:72], out[79:72]),
        S_7 (clk, in[71:64],  out[71:64]),
        S_8 (clk, in[63:56], out[63:56]),
        S_9 (clk, in[55:48], out[55:48]),
        S_10 (clk, in[47:40], out[47:40]),
        S_11 (clk, in[39:32],  out[39:32]),
        S_12 (clk, in[31:24], out[31:24]),
        S_13 (clk, in[23:16], out[23:16]),
        S_14 (clk, in[15:8], out[15:8]),
        S_15 (clk, in[7:0],  out[7:0]);
endmodule

module invS16 (clk, in, out);
    input clk;
    input [127:0] in;
    output [127:0] out;

    invS
        invS_0 (clk, in[127:120], out[127:120]),
        invS_1 (clk, in[119:112], out[119:112]),
        invS_2 (clk, in[111:104], out[111:104]),
        invS_3 (clk, in[103:96],  out[103:96]),
        invS_4 (clk, in[95:88], out[95:88]),
        invS_5 (clk, in[87:80], out[87:80]),
        invS_6 (clk, in[79:72], out[79:72]),
        invS_7 (clk, in[71:64],  out[71:64]),
        invS_8 (clk, in[63:56], out[63:56]),
        invS_9 (clk, in[55:48], out[55:48]),
        invS_10 (clk, in[47:40], out[47:40]),
        invS_11 (clk, in[39:32],  out[39:32]),
        invS_12 (clk, in[31:24], out[31:24]),
        invS_13 (clk, in[23:16], out[23:16]),
        invS_14 (clk, in[15:8], out[15:8]),
        invS_15 (clk, in[7:0],  out[7:0]);
endmodule


//[127:120] [119:112] [111:104] [103:96] [95:88] [87:80] [79:72] [71:64][63:56] [55:48]
//[47:40] [39:32] [31:24] [23:16] [15:8] [7:0]


module XWord (in, out);
    input [127:0] in;
    output [127:0] out;
    wire [7:0] x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15;
    wire [7:0] y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15;

	 assign {x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15} = in;


	 assign y0 = x4 ^ x8 ^ x12;
	 assign y1 = x5 ^ x9 ^ x13;
	 assign y2 = x6 ^ x10 ^ x14;
	 assign y3 = x7 ^ x11 ^ x15;
	 assign y4 = x8 ^ x12 ^ x0;
	 assign y5 = x9 ^ x13 ^ x1;
	 assign y6 = x10 ^ x14 ^ x2;
	 assign y7 = x11 ^ x15 ^ x3;
	 assign y8 = x12 ^ x0 ^ x4;
	 assign y9 = x13 ^ x1 ^ x5;
	 assign y10 = x14 ^ x2 ^ x6;
	 assign y11 = x15 ^ x3 ^ x7;
	 assign y12 = x0 ^ x4 ^ x8;
	 assign y13 = x1 ^ x5 ^ x9;
	 assign y14 = x2 ^ x6 ^ x10;
	 assign y15 = x3 ^ x7 ^ x11;

	 assign out = {y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15};

endmodule



//[63:56] [55:48] [47:40] [39:32] [31:24] [23:16] [15:8] [7:0]
module Mix_column (in, out);
    input [127:0] in;
    output [127:0] out;

	function [7 : 0] M2(input [7 : 0] in);
		 begin
             M2[7] = in[6];
             M2[6] = in[5];
             M2[5] = in[4] ^ in[7];
             M2[4] = in[3];
             M2[3] = in[2] ^ in[7];
             M2[2] = in[1];
             M2[1] = in[0] ^ in[7];
             M2[0] = in[7];
		 end
	endfunction



   wire [7:0] x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15;
   wire [7:0] y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15;

	 assign {x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15} = in;


		 assign y0 = x0 ^ x2 ^ x3 ^ M2(x1 ^ x3);
		 assign y1 = x1 ^ x3 ^ y0 ^ M2(x2 ^ y0);
		 assign y2 = x2 ^ y0 ^ y1 ^ M2(x3 ^ y1);
		 assign y3 = x3 ^ y1 ^ y2 ^ M2(y0 ^ y2);

		 assign y4 = x5 ^ x7 ^ x4 ^ M2(x6 ^ x4);
		 assign y5 = x6 ^ x4 ^ y4 ^ M2(x7 ^ y4);
		 assign y6 = x7 ^ y4 ^ y5 ^ M2(x4 ^ y5);
		 assign y7 = x4 ^ y5 ^ y6 ^ M2(y4 ^ y6);

		 assign y8 = x10 ^ x8 ^ x9 ^ M2(x11 ^ x9);
		 assign y9 = x11 ^ x9 ^ y8 ^ M2(x8 ^ y8);
		 assign y10 = x8 ^ y8 ^ y9 ^ M2(x9 ^ y9);
		 assign y11 = x9 ^ y9 ^ y10 ^ M2(y8 ^ y10);

		 assign y12 = x15 ^ x13 ^ x14 ^ M2(x12 ^ x14);
		 assign y13 = x12 ^ x14 ^ y12 ^ M2(x13 ^ y12);
		 assign y14 = x13 ^ y12 ^ y13 ^ M2(x14 ^ y13);
		 assign y15 = x14 ^ y13 ^ y14 ^ M2(y12 ^ y14);

	 assign out = {y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15};

endmodule

module InvMix_column (in, out);
    input [127:0] in;
    output [127:0] out;

	function [7 : 0] M2(input [7 : 0] in);
		 begin
             M2[7] = in[6];
             M2[6] = in[5];
             M2[5] = in[4] ^ in[7];
             M2[4] = in[3];
             M2[3] = in[2] ^ in[7];
             M2[2] = in[1];
             M2[1] = in[0] ^ in[7];
             M2[0] = in[7];
		 end
	endfunction



   wire [7:0] x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15;
   wire [7:0] y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15;

	 assign {x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15} = in;


		 assign y3 = x1 ^ x2 ^ x3 ^ M2(x0 ^ x2);
		 assign y2 = x0 ^ x1 ^ x2 ^ M2(y3 ^ x1);
		 assign y1 = y3 ^ x0 ^ x1 ^ M2(y2 ^ x0);
		 assign y0 = y2 ^ y3 ^ x0 ^ M2(y1 ^ y3);

         assign y4 = x5 ^ x6 ^ x7 ^ M2(x4 ^ x6);
		 assign y7 = x4 ^ x5 ^ x6 ^ M2(y4 ^ x5);
		 assign y6 = x5 ^ x4 ^ y4 ^ M2(y7 ^ x4);
		 assign y5 = x4 ^ y7 ^ y4 ^ M2(y6 ^ y4);

         assign y9 = x9 ^ x10 ^ x11 ^ M2(x8 ^ x10);
         assign y8 = x8 ^ x9 ^ x10 ^ M2(y9 ^ x9);
		 assign y11 = y9 ^ x8 ^ x9 ^ M2(y8 ^ x8);
		 assign y10 = y8 ^ y9 ^ x8 ^ M2(y11 ^ y9);

		 assign y14 = x13 ^ x14 ^ x15 ^ M2(x12 ^ x14);
		 assign y13 = x12 ^ x13 ^ x14 ^ M2(y14 ^ x13);
		 assign y12 = x13 ^ x12 ^ y14 ^ M2(y13 ^ x12);
		 assign y15 = x12 ^ y13 ^ y14 ^ M2(y12 ^ y14);




	 assign out = {y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,y10,y11,y12,y13,y14,y15};

endmodule


module SubCells (
  input  wire [127:0] X,
  output wire [127:0] Y
);
  //
  assign Y = { s(X[127:120]), s(X[119:112]), s(X[111:104]), s(X[103: 96]),
               s(X[ 95: 88]), s(X[ 87: 80]), s(X[ 79: 72]), s(X[ 71: 64]),
               s(X[ 63: 56]), s(X[ 55: 48]), s(X[ 47: 40]), s(X[ 39: 32]),
               s(X[ 31: 24]), s(X[ 23: 16]), s(X[ 15:  8]), s(X[  7:   0]) };

  //
  function [7:0] s;
    input [7:0] x;
    case(x)
      8'h00: s=8'h01; 8'h01: s=8'h11; 8'h02: s=8'h91; 8'h03: s=8'hE1;
      8'h04: s=8'hD1; 8'h05: s=8'hB1; 8'h06: s=8'h71; 8'h07: s=8'h61;
      8'h08: s=8'hF1; 8'h09: s=8'h21; 8'h0A: s=8'hC1; 8'h0B: s=8'h51;
      8'h0C: s=8'hA1; 8'h0D: s=8'h41; 8'h0E: s=8'h31; 8'h0F: s=8'h81;

      8'h10: s=8'h00; 8'h11: s=8'h10; 8'h12: s=8'hE3; 8'h13: s=8'h92;
      8'h14: s=8'hB5; 8'h15: s=8'hD4; 8'h16: s=8'h77; 8'h17: s=8'h66;
      8'h18: s=8'h89; 8'h19: s=8'h38; 8'h1A: s=8'hAB; 8'h1B: s=8'h4A;
      8'h1C: s=8'hCD; 8'h1D: s=8'h5C; 8'h1E: s=8'h2F; 8'h1F: s=8'hFE;

      8'h20: s=8'h08; 8'h21: s=8'h5F; 8'h22: s=8'h3E; 8'h23: s=8'hB0;
      8'h24: s=8'h1C; 8'h25: s=8'hC2; 8'h26: s=8'h83; 8'h27: s=8'hDD;
      8'h28: s=8'hE8; 8'h29: s=8'hF6; 8'h2A: s=8'h47; 8'h2B: s=8'h79;
      8'h2C: s=8'h95; 8'h2D: s=8'h2B; 8'h2E: s=8'hAA; 8'h2F: s=8'h64;

      8'h30: s=8'h0F; 8'h31: s=8'h48; 8'h32: s=8'hD0; 8'h33: s=8'h29;
      8'h34: s=8'hA3; 8'h35: s=8'h1A; 8'h36: s=8'hF2; 8'h37: s=8'hBB;
      8'h38: s=8'h65; 8'h39: s=8'hCC; 8'h3A: s=8'hE4; 8'h3B: s=8'h3D;
      8'h3C: s=8'h57; 8'h3D: s=8'h7E; 8'h3E: s=8'h86; 8'h3F: s=8'h9F;

      8'h40: s=8'h0C; 8'h41: s=8'h2A; 8'h42: s=8'hF4; 8'h43: s=8'h1F;
      8'h44: s=8'h5B; 8'h45: s=8'h90; 8'h46: s=8'hEE; 8'h47: s=8'hC5;
      8'h48: s=8'h36; 8'h49: s=8'h6D; 8'h4A: s=8'h73; 8'h4B: s=8'h88;
      8'h4C: s=8'hBC; 8'h4D: s=8'hA7; 8'h4E: s=8'h49; 8'h4F: s=8'hD2;

      8'h50: s=8'h0A; 8'h51: s=8'h3C; 8'h52: s=8'h18; 8'h53: s=8'h85;
      8'h54: s=8'hE0; 8'h55: s=8'h4D; 8'h56: s=8'h99; 8'h57: s=8'hA4;
      8'h58: s=8'hB3; 8'h59: s=8'h5E; 8'h5A: s=8'hDA; 8'h5B: s=8'hC7;
      8'h5C: s=8'h72; 8'h5D: s=8'hFF; 8'h5E: s=8'h6B; 8'h5F: s=8'h26;

      8'h60: s=8'h06; 8'h61: s=8'h76; 8'h62: s=8'hCF; 8'h63: s=8'hA8;
      8'h64: s=8'h4E; 8'h65: s=8'h59; 8'h66: s=8'h60; 8'h67: s=8'h17;
      8'h68: s=8'hDC; 8'h69: s=8'h9B; 8'h6A: s=8'h32; 8'h6B: s=8'hF5;
      8'h6C: s=8'h23; 8'h6D: s=8'h84; 8'h6E: s=8'hED; 8'h6F: s=8'hBA;

      8'h70: s=8'h07; 8'h71: s=8'h67; 8'h72: s=8'h2D; 8'h73: s=8'h3B;
      8'h74: s=8'hFA; 8'h75: s=8'h8C; 8'h76: s=8'h16; 8'h77: s=8'h70;
      8'h78: s=8'h54; 8'h79: s=8'hA2; 8'h7A: s=8'h98; 8'h7B: s=8'hBE;
      8'h7C: s=8'hEF; 8'h7D: s=8'hD9; 8'h7E: s=8'hC3; 8'h7F: s=8'h45;

      8'h80: s=8'h0E; 8'h81: s=8'hA9; 8'h82: s=8'h62; 8'h83: s=8'h5A;
      8'h84: s=8'h27; 8'h85: s=8'hBF; 8'h86: s=8'h34; 8'h87: s=8'h9C;
      8'h88: s=8'hFD; 8'h89: s=8'hD5; 8'h8A: s=8'h8E; 8'h8B: s=8'hE6;
      8'h8C: s=8'h1B; 8'h8D: s=8'h43; 8'h8E: s=8'h78; 8'h8F: s=8'hC0;

      8'h90: s=8'h03; 8'h91: s=8'hB2; 8'h92: s=8'h87; 8'h93: s=8'hC4;
      8'h94: s=8'h9D; 8'h95: s=8'h6E; 8'h96: s=8'h4B; 8'h97: s=8'hF8;
      8'h98: s=8'h7A; 8'h99: s=8'hE9; 8'h9A: s=8'h2C; 8'h9B: s=8'hAF;
      8'h9C: s=8'hD6; 8'h9D: s=8'h15; 8'h9E: s=8'h50; 8'h9F: s=8'h33;

      8'hA0: s=8'h0D; 8'hA1: s=8'hFB; 8'hA2: s=8'h56; 8'hA3: s=8'hEC;
      8'hA4: s=8'h3F; 8'hA5: s=8'h75; 8'hA6: s=8'hB8; 8'hA7: s=8'h42;
      8'hA8: s=8'h1E; 8'hA9: s=8'h24; 8'hAA: s=8'hC9; 8'hAB: s=8'h93;
      8'hAC: s=8'h80; 8'hAD: s=8'h6A; 8'hAE: s=8'hD7; 8'hAF: s=8'hAD;

      8'hB0: s=8'h04; 8'hB1: s=8'hE5; 8'hB2: s=8'hB9; 8'hB3: s=8'h7D;
      8'hB4: s=8'h82; 8'hB5: s=8'hA6; 8'hB6: s=8'hCA; 8'hB7: s=8'h2E;
      8'hB8: s=8'h97; 8'hB9: s=8'h13; 8'hBA: s=8'h6F; 8'hBB: s=8'hDB;
      8'hBC: s=8'h44; 8'hBD: s=8'h30; 8'hBE: s=8'hFC; 8'hBF: s=8'h58;

      8'hC0: s=8'h0B; 8'hC1: s=8'h8D; 8'hC2: s=8'h9A; 8'hC3: s=8'h46;
      8'hC4: s=8'h74; 8'hC5: s=8'h28; 8'hC6: s=8'hDF; 8'hC7: s=8'h53;
      8'hC8: s=8'hCB; 8'hC9: s=8'hB7; 8'hCA: s=8'hF0; 8'hCB: s=8'h6C;
      8'hCC: s=8'hAE; 8'hCD: s=8'hE2; 8'hCE: s=8'h35; 8'hCF: s=8'h19;

      8'hD0: s=8'h05; 8'hD1: s=8'h94; 8'hD2: s=8'h7B; 8'hD3: s=8'hDE;
      8'hD4: s=8'hC6; 8'hD5: s=8'hF3; 8'hD6: s=8'hAC; 8'hD7: s=8'h39;
      8'hD8: s=8'h4F; 8'hD9: s=8'h8A; 8'hDA: s=8'h55; 8'hDB: s=8'h20;
      8'hDC: s=8'h68; 8'hDD: s=8'hBD; 8'hDE: s=8'h12; 8'hDF: s=8'hE7;

      8'hE0: s=8'h02; 8'hE1: s=8'hD3; 8'hE2: s=8'hA5; 8'hE3: s=8'hF7;
      8'hE4: s=8'h69; 8'hE5: s=8'hEB; 8'hE6: s=8'h5D; 8'hE7: s=8'h8F;
      8'hE8: s=8'h22; 8'hE9: s=8'h40; 8'hEA: s=8'hB6; 8'hEB: s=8'h14;
      8'hEC: s=8'h3A; 8'hED: s=8'hC8; 8'hEE: s=8'h9E; 8'hEF: s=8'h7C;

      8'hF0: s=8'h09; 8'hF1: s=8'hCE; 8'hF2: s=8'h4C; 8'hF3: s=8'h63;
      8'hF4: s=8'hD8; 8'hF5: s=8'h37; 8'hF6: s=8'h25; 8'hF7: s=8'hEA;
      8'hF8: s=8'hA0; 8'hF9: s=8'h7F; 8'hFA: s=8'h1D; 8'hFB: s=8'h52;
      8'hFC: s=8'hF9; 8'hFD: s=8'h96; 8'hFE: s=8'hB4; 8'hFF: s=8'h8B;

      default: s = 8'h00;
    endcase
  endfunction

endmodule

module InvSubcells (
  input  wire [127:0] X,
  output wire [127:0] Y
);
  // Apply inverse S-box to each byte
  assign Y = { inv_s(X[127:120]), inv_s(X[119:112]), inv_s(X[111:104]), inv_s(X[103: 96]),
               inv_s(X[ 95: 88]), inv_s(X[ 87: 80]), inv_s(X[ 79: 72]), inv_s(X[ 71: 64]),
               inv_s(X[ 63: 56]), inv_s(X[ 55: 48]), inv_s(X[ 47: 40]), inv_s(X[ 39: 32]),
               inv_s(X[ 31: 24]), inv_s(X[ 23: 16]), inv_s(X[ 15:  8]), inv_s(X[  7:   0]) };

  // Inverse S-box function for MKV
  function [7:0] inv_s;
    input [7:0] x;
    case(x)
      8'h00: inv_s = 8'h10;  8'h01: inv_s = 8'h00;  8'h02: inv_s = 8'hE0;  8'h03: inv_s = 8'h90;
      8'h04: inv_s = 8'hB0;  8'h05: inv_s = 8'hD0;  8'h06: inv_s = 8'h60;  8'h07: inv_s = 8'h70;
      8'h08: inv_s = 8'h20;  8'h09: inv_s = 8'hF0;  8'h0A: inv_s = 8'h50;  8'h0B: inv_s = 8'hC0;
      8'h0C: inv_s = 8'h40;  8'h0D: inv_s = 8'hA0;  8'h0E: inv_s = 8'h80;  8'h0F: inv_s = 8'h30;
      8'h10: inv_s = 8'h11;  8'h11: inv_s = 8'h01;  8'h12: inv_s = 8'hDE;  8'h13: inv_s = 8'hB9;
      8'h14: inv_s = 8'hEB;  8'h15: inv_s = 8'h9D;  8'h16: inv_s = 8'h76;  8'h17: inv_s = 8'h67;
      8'h18: inv_s = 8'h52;  8'h19: inv_s = 8'hCF;  8'h1A: inv_s = 8'h35;  8'h1B: inv_s = 8'h8C;
      8'h1C: inv_s = 8'h24;  8'h1D: inv_s = 8'hFA;  8'h1E: inv_s = 8'hA8;  8'h1F: inv_s = 8'h43;
      8'h20: inv_s = 8'hDB;  8'h21: inv_s = 8'h09;  8'h22: inv_s = 8'hE8;  8'h23: inv_s = 8'h6C;
      8'h24: inv_s = 8'hA9;  8'h25: inv_s = 8'hF6;  8'h26: inv_s = 8'h5F;  8'h27: inv_s = 8'h84;
      8'h28: inv_s = 8'hC5;  8'h29: inv_s = 8'h33;  8'h2A: inv_s = 8'h41;  8'h2B: inv_s = 8'h2D;
      8'h2C: inv_s = 8'h9A;  8'h2D: inv_s = 8'h72;  8'h2E: inv_s = 8'hB7;  8'h2F: inv_s = 8'h1E;
      8'h30: inv_s = 8'hBD;  8'h31: inv_s = 8'h0E;  8'h32: inv_s = 8'h6A;  8'h33: inv_s = 8'h9F;
      8'h34: inv_s = 8'h86;  8'h35: inv_s = 8'hCE;  8'h36: inv_s = 8'h48;  8'h37: inv_s = 8'hF5;
      8'h38: inv_s = 8'h19;  8'h39: inv_s = 8'hD7;  8'h3A: inv_s = 8'hEC;  8'h3B: inv_s = 8'h73;
      8'h3C: inv_s = 8'h51;  8'h3D: inv_s = 8'h3B;  8'h3E: inv_s = 8'h22;  8'h3F: inv_s = 8'hA4;
      8'h40: inv_s = 8'hE9;  8'h41: inv_s = 8'h0D;  8'h42: inv_s = 8'hA7;  8'h43: inv_s = 8'h8D;
      8'h44: inv_s = 8'hBC;  8'h45: inv_s = 8'h7F;  8'h46: inv_s = 8'hC3;  8'h47: inv_s = 8'h2A;
      8'h48: inv_s = 8'h31;  8'h49: inv_s = 8'h4E;  8'h4A: inv_s = 8'h1B;  8'h4B: inv_s = 8'h96;
      8'h4C: inv_s = 8'hF2;  8'h4D: inv_s = 8'h55;  8'h4E: inv_s = 8'h64;  8'h4F: inv_s = 8'hD8;
      8'h50: inv_s = 8'h9E;  8'h51: inv_s = 8'h0B;  8'h52: inv_s = 8'hFB;  8'h53: inv_s = 8'hC7;
      8'h54: inv_s = 8'h78;  8'h55: inv_s = 8'hDA;  8'h56: inv_s = 8'hA2;  8'h57: inv_s = 8'h3C;
      8'h58: inv_s = 8'hBF;  8'h59: inv_s = 8'h65;  8'h5A: inv_s = 8'h83;  8'h5B: inv_s = 8'h44;
      8'h5C: inv_s = 8'h1D;  8'h5D: inv_s = 8'hE6;  8'h5E: inv_s = 8'h59;  8'h5F: inv_s = 8'h21;
      8'h60: inv_s = 8'h66;  8'h61: inv_s = 8'h07;  8'h62: inv_s = 8'h82;  8'h63: inv_s = 8'hF3;
      8'h64: inv_s = 8'h2F;  8'h65: inv_s = 8'h38;  8'h66: inv_s = 8'h17;  8'h67: inv_s = 8'h71;
      8'h68: inv_s = 8'hDC;  8'h69: inv_s = 8'hE4;  8'h6A: inv_s = 8'hAD;  8'h6B: inv_s = 8'h5E;
      8'h6C: inv_s = 8'hCB;  8'h6D: inv_s = 8'h49;  8'h6E: inv_s = 8'h95;  8'h6F: inv_s = 8'hBA;
      8'h70: inv_s = 8'h77;  8'h71: inv_s = 8'h06;  8'h72: inv_s = 8'h5C;  8'h73: inv_s = 8'h4A;
      8'h74: inv_s = 8'hC4;  8'h75: inv_s = 8'hA5;  8'h76: inv_s = 8'h61;  8'h77: inv_s = 8'h16;
      8'h78: inv_s = 8'h8E;  8'h79: inv_s = 8'h2B;  8'h7A: inv_s = 8'h98;  8'h7B: inv_s = 8'hD2;
      8'h7C: inv_s = 8'hEF;  8'h7D: inv_s = 8'hB3;  8'h7E: inv_s = 8'h3D;  8'h7F: inv_s = 8'hF9;
      8'h80: inv_s = 8'hAC;  8'h81: inv_s = 8'h0F;  8'h82: inv_s = 8'hB4;  8'h83: inv_s = 8'h26;
      8'h84: inv_s = 8'h6D;  8'h85: inv_s = 8'h53;  8'h86: inv_s = 8'h3E;  8'h87: inv_s = 8'h92;
      8'h88: inv_s = 8'h4B;  8'h89: inv_s = 8'h18;  8'h8A: inv_s = 8'hD9;  8'h8B: inv_s = 8'hFF;
      8'h8C: inv_s = 8'h75;  8'h8D: inv_s = 8'hC1;  8'h8E: inv_s = 8'h8A;  8'h8F: inv_s = 8'hE7;
      8'h90: inv_s = 8'h45;  8'h91: inv_s = 8'h02;  8'h92: inv_s = 8'h13;  8'h93: inv_s = 8'hAB;
      8'h94: inv_s = 8'hD1;  8'h95: inv_s = 8'h2C;  8'h96: inv_s = 8'hFD;  8'h97: inv_s = 8'hB8;
      8'h98: inv_s = 8'h7A;  8'h99: inv_s = 8'h56;  8'h9A: inv_s = 8'hC2;  8'h9B: inv_s = 8'h69;
      8'h9C: inv_s = 8'h87;  8'h9D: inv_s = 8'h94;  8'h9E: inv_s = 8'hEE;  8'h9F: inv_s = 8'h3F;
      8'hA0: inv_s = 8'hF8;  8'hA1: inv_s = 8'h0C;  8'hA2: inv_s = 8'h79;  8'hA3: inv_s = 8'h34;
      8'hA4: inv_s = 8'h57;  8'hA5: inv_s = 8'hE2;  8'hA6: inv_s = 8'hB5;  8'hA7: inv_s = 8'h4D;
      8'hA8: inv_s = 8'h63;  8'hA9: inv_s = 8'h81;  8'hAA: inv_s = 8'h2E;  8'hAB: inv_s = 8'h1A;
      8'hAC: inv_s = 8'hD6;  8'hAD: inv_s = 8'hAF;  8'hAE: inv_s = 8'hCC;  8'hAF: inv_s = 8'h9B;
      8'hB0: inv_s = 8'h23;  8'hB1: inv_s = 8'h05;  8'hB2: inv_s = 8'h91;  8'hB3: inv_s = 8'h58;
      8'hB4: inv_s = 8'hFE;  8'hB5: inv_s = 8'h14;  8'hB6: inv_s = 8'hEA;  8'hB7: inv_s = 8'hC9;
      8'hB8: inv_s = 8'hA6;  8'hB9: inv_s = 8'hB2;  8'hBA: inv_s = 8'h6F;  8'hBB: inv_s = 8'h37;
      8'hBC: inv_s = 8'h4C;  8'hBD: inv_s = 8'hDD;  8'hBE: inv_s = 8'h7B;  8'hBF: inv_s = 8'h85;
      8'hC0: inv_s = 8'h8F;  8'hC1: inv_s = 8'h0A;  8'hC2: inv_s = 8'h25;  8'hC3: inv_s = 8'h7E;
      8'hC4: inv_s = 8'h93;  8'hC5: inv_s = 8'h47;  8'hC6: inv_s = 8'hD4;  8'hC7: inv_s = 8'h5B;
      8'hC8: inv_s = 8'hED;  8'hC9: inv_s = 8'hAA;  8'hCA: inv_s = 8'hB6;  8'hCB: inv_s = 8'hC8;
      8'hCC: inv_s = 8'h39;  8'hCD: inv_s = 8'h1C;  8'hCE: inv_s = 8'hF1;  8'hCF: inv_s = 8'h62;
      8'hD0: inv_s = 8'h32;  8'hD1: inv_s = 8'h04;  8'hD2: inv_s = 8'h4F;  8'hD3: inv_s = 8'hE1;
      8'hD4: inv_s = 8'h15;  8'hD5: inv_s = 8'h89;  8'hD6: inv_s = 8'h9C;  8'hD7: inv_s = 8'hAE;
      8'hD8: inv_s = 8'hF4;  8'hD9: inv_s = 8'h7D;  8'hDA: inv_s = 8'h5A;  8'hDB: inv_s = 8'hBB;
      8'hDC: inv_s = 8'h68;  8'hDD: inv_s = 8'h27;  8'hDE: inv_s = 8'hD3;  8'hDF: inv_s = 8'hC6;
      8'hE0: inv_s = 8'h54;  8'hE1: inv_s = 8'h03;  8'hE2: inv_s = 8'hCD;  8'hE3: inv_s = 8'h12;
      8'hE4: inv_s = 8'h3A;  8'hE5: inv_s = 8'hB1;  8'hE6: inv_s = 8'h8B;  8'hE7: inv_s = 8'hDF;
      8'hE8: inv_s = 8'h28;  8'hE9: inv_s = 8'h99;  8'hEA: inv_s = 8'hF7;  8'hEB: inv_s = 8'hE5;
      8'hEC: inv_s = 8'hA3;  8'hED: inv_s = 8'h6E;  8'hEE: inv_s = 8'h46;  8'hEF: inv_s = 8'h7C;
      8'hF0: inv_s = 8'hCA;  8'hF1: inv_s = 8'h08;  8'hF2: inv_s = 8'h36;  8'hF3: inv_s = 8'hD5;
      8'hF4: inv_s = 8'h42;  8'hF5: inv_s = 8'h6B;  8'hF6: inv_s = 8'h29;  8'hF7: inv_s = 8'hE3;
      8'hF8: inv_s = 8'h97;  8'hF9: inv_s = 8'hFC;  8'hFA: inv_s = 8'h74;  8'hFB: inv_s = 8'hA1;
      8'hFC: inv_s = 8'hBE;  8'hFD: inv_s = 8'h88;  8'hFE: inv_s = 8'h1F;  8'hFF: inv_s = 8'h5D;
      default: inv_s = 8'h00;
    endcase
  endfunction
endmodule




/* S(a)*/
module S (clk, in, out);
    input clk;
    input [7:0] in;
    output reg [7:0] out;

    always @ (posedge clk)
    case (in)
    8'h00: out <= 8'h01;

    8'h01: out <= 8'h11;

    8'h02: out <= 8'h91;

    8'h03: out <= 8'hE1;

    8'h04: out <= 8'hD1;

    8'h05: out <= 8'hB1;

    8'h06: out <= 8'h71;

    8'h07: out <= 8'h61;

    8'h08: out <= 8'hF1;

    8'h09: out <= 8'h21;

    8'h0a: out <= 8'hC1;

    8'h0b: out <= 8'h51;

    8'h0c: out <= 8'hA1;

    8'h0d: out <= 8'h41;

    8'h0e: out <= 8'h31;

    8'h0f: out <= 8'h81;

    8'h10: out <= 8'h00;

    8'h11: out <= 8'h10;

    8'h12: out <= 8'hE3;

    8'h13: out <= 8'h92;

    8'h14: out <= 8'hB5;

    8'h15: out <= 8'hD4;

    8'h16: out <= 8'h77;

    8'h17: out <= 8'h66;

    8'h18: out <= 8'h89;

    8'h19: out <= 8'h38;

    8'h1a: out <= 8'hAB;

    8'h1b: out <= 8'h4A;

    8'h1c: out <= 8'hCD;

    8'h1d: out <= 8'h5C;

    8'h1e: out <= 8'h2F;

    8'h1f: out <= 8'hFE;

    8'h20: out <= 8'h08;

    8'h21: out <= 8'h5F;

    8'h22: out <= 8'h3E;

    8'h23: out <= 8'hB0;

    8'h24: out <= 8'h1C;

    8'h25: out <= 8'hC2;

    8'h26: out <= 8'h83;

    8'h27: out <= 8'hDD;

    8'h28: out <= 8'hE8;

    8'h29: out <= 8'hF6;

    8'h2a: out <= 8'h47;

    8'h2b: out <= 8'h79;

    8'h2c: out <= 8'h95;

    8'h2d: out <= 8'h2B;

    8'h2e: out <= 8'hAA;

    8'h2f: out <= 8'h64;

    8'h30: out <= 8'h0F;

    8'h31: out <= 8'h48;

    8'h32: out <= 8'hD0;

    8'h33: out <= 8'h29;

    8'h34: out <= 8'hA3;

    8'h35: out <= 8'h1A;

    8'h36: out <= 8'hF2;

    8'h37: out <= 8'hBB;

    8'h38: out <= 8'h65;

    8'h39: out <= 8'hCC;

    8'h3a: out <= 8'hE4;

    8'h3b: out <= 8'h3D;

    8'h3c: out <= 8'h57;

    8'h3d: out <= 8'h7E;

    8'h3e: out <= 8'h86;

    8'h3f: out <= 8'h9F;

    8'h40: out <= 8'h0C;

    8'h41: out <= 8'h2A;

    8'h42: out <= 8'hF4;

    8'h43: out <= 8'h1F;

    8'h44: out <= 8'h5B;

    8'h45: out <= 8'h90;

    8'h46: out <= 8'hEE;

    8'h47: out <= 8'hC5;

    8'h48: out <= 8'h36;

    8'h49: out <= 8'h6D;

    8'h4a: out <= 8'h73;

    8'h4b: out <= 8'h88;

    8'h4c: out <= 8'hBC;

    8'h4d: out <= 8'hA7;

    8'h4e: out <= 8'h49;

    8'h4f: out <= 8'hD2;

    8'h50: out <= 8'h0A;

    8'h51: out <= 8'h3C;

    8'h52: out <= 8'h18;

    8'h53: out <= 8'h85;

    8'h54: out <= 8'hE0;

    8'h55: out <= 8'h4D;

    8'h56: out <= 8'h99;

    8'h57: out <= 8'hA4;

    8'h58: out <= 8'hB3;

    8'h59: out <= 8'h5E;

    8'h5a: out <= 8'hDA;

    8'h5b: out <= 8'hC7;

    8'h5c: out <= 8'h72;

    8'h5d: out <= 8'hFF;

    8'h5e: out <= 8'h6B;

    8'h5f: out <= 8'h26;

    8'h60: out <= 8'h06;

    8'h61: out <= 8'h76;

    8'h62: out <= 8'hCF;

    8'h63: out <= 8'hA8;

    8'h64: out <= 8'h4E;

    8'h65: out <= 8'h59;

    8'h66: out <= 8'h60;

    8'h67: out <= 8'h17;

    8'h68: out <= 8'hDC;

    8'h69: out <= 8'h9B;

    8'h6a: out <= 8'h32;

    8'h6b: out <= 8'hF5;

    8'h6c: out <= 8'h23;

    8'h6d: out <= 8'h84;

    8'h6e: out <= 8'hED;

    8'h6f: out <= 8'hBA;

    8'h70: out <= 8'h07;

    8'h71: out <= 8'h67;

    8'h72: out <= 8'h2D;

    8'h73: out <= 8'h3B;

    8'h74: out <= 8'hFA;

    8'h75: out <= 8'h8C;

    8'h76: out <= 8'h16;

    8'h77: out <= 8'h70;

    8'h78: out <= 8'h54;

    8'h79: out <= 8'hA2;

    8'h7a: out <= 8'h98;

    8'h7b: out <= 8'hBE;

    8'h7c: out <= 8'hEF;

    8'h7d: out <= 8'hD9;

    8'h7e: out <= 8'hC3;

    8'h7f: out <= 8'h45;

    8'h80: out <= 8'h0E;

    8'h81: out <= 8'hA9;

    8'h82: out <= 8'h62;

    8'h83: out <= 8'h5A;

    8'h84: out <= 8'h27;

    8'h85: out <= 8'hBF;

    8'h86: out <= 8'h34;

    8'h87: out <= 8'h9C;

    8'h88: out <= 8'hFD;

    8'h89: out <= 8'hD5;

    8'h8a: out <= 8'h8E;

    8'h8b: out <= 8'hE6;

    8'h8c: out <= 8'h1B;

    8'h8d: out <= 8'h43;

    8'h8e: out <= 8'h78;

    8'h8f: out <= 8'hC0;

    8'h90: out <= 8'h03;

    8'h91: out <= 8'hB2;

    8'h92: out <= 8'h87;

    8'h93: out <= 8'hC4;

    8'h94: out <= 8'h9D;

    8'h95: out <= 8'h6E;

    8'h96: out <= 8'h4B;

    8'h97: out <= 8'hF8;

    8'h98: out <= 8'h7A;

    8'h99: out <= 8'hE9;

    8'h9a: out <= 8'h2C;

    8'h9b: out <= 8'hAF;

    8'h9c: out <= 8'hD6;

    8'h9d: out <= 8'h15;

    8'h9e: out <= 8'h50;

    8'h9f: out <= 8'h33;

    8'ha0: out <= 8'h0D;

    8'ha1: out <= 8'hFB;

    8'ha2: out <= 8'h56;

    8'ha3: out <= 8'hEC;

    8'ha4: out <= 8'h3F;

    8'ha5: out <= 8'h75;

    8'ha6: out <= 8'hB8;

    8'ha7: out <= 8'h42;

    8'ha8: out <= 8'h1E;

    8'ha9: out <= 8'h24;

    8'haa: out <= 8'hC9;

    8'hab: out <= 8'h93;

    8'hac: out <= 8'h80;

    8'had: out <= 8'h6A;

    8'hae: out <= 8'hD7;

    8'haf: out <= 8'hAD;

    8'hb0: out <= 8'h04;

    8'hb1: out <= 8'hE5;

    8'hb2: out <= 8'hB9;

    8'hb3: out <= 8'h7D;

    8'hb4: out <= 8'h82;

    8'hb5: out <= 8'hA6;

    8'hb6: out <= 8'hCA;

    8'hb7: out <= 8'h2E;

    8'hb8: out <= 8'h97;

    8'hb9: out <= 8'h13;

    8'hba: out <= 8'h6F;

    8'hbb: out <= 8'hDB;

    8'hbc: out <= 8'h44;

    8'hbd: out <= 8'h30;

    8'hbe: out <= 8'hFC;

    8'hbf: out <= 8'h58;

    8'hc0: out <= 8'h0B;

    8'hc1: out <= 8'h8D;

    8'hc2: out <= 8'h9A;

    8'hc3: out <= 8'h46;

    8'hc4: out <= 8'h74;

    8'hc5: out <= 8'h28;

    8'hc6: out <= 8'hDF;

    8'hc7: out <= 8'h53;

    8'hc8: out <= 8'hCB;

    8'hc9: out <= 8'hB7;

    8'hca: out <= 8'hF0;

    8'hcb: out <= 8'h6C;

    8'hcc: out <= 8'hAE;

    8'hcd: out <= 8'hE2;

    8'hce: out <= 8'h35;

    8'hcf: out <= 8'h19;

    8'hd0: out <= 8'h05;

    8'hd1: out <= 8'h94;

    8'hd2: out <= 8'h7B;

    8'hd3: out <= 8'hDE;

    8'hd4: out <= 8'hC6;

    8'hd5: out <= 8'hF3;

    8'hd6: out <= 8'hAC;

    8'hd7: out <= 8'h39;

    8'hd8: out <= 8'h4F;

    8'hd9: out <= 8'h8A;

    8'hda: out <= 8'h55;

    8'hdb: out <= 8'h20;

    8'hdc: out <= 8'h68;

    8'hdd: out <= 8'hBD;

    8'hde: out <= 8'h12;

    8'hdf: out <= 8'hE7;

    8'he0: out <= 8'h02;

    8'he1: out <= 8'hD3;

    8'he2: out <= 8'hA5;

    8'he3: out <= 8'hF7;

    8'he4: out <= 8'h69;

    8'he5: out <= 8'hEB;

    8'he6: out <= 8'h5D;

    8'he7: out <= 8'h8F;

    8'he8: out <= 8'h22;

    8'he9: out <= 8'h40;

    8'hea: out <= 8'hB6;

    8'heb: out <= 8'h14;

    8'hec: out <= 8'h3A;

    8'hed: out <= 8'hC8;

    8'hee: out <= 8'h9E;

    8'hef: out <= 8'h7C;

    8'hf0: out <= 8'h09;

    8'hf1: out <= 8'hCE;

    8'hf2: out <= 8'h4C;

    8'hf3: out <= 8'h63;

    8'hf4: out <= 8'hD8;

    8'hf5: out <= 8'h37;

    8'hf6: out <= 8'h25;

    8'hf7: out <= 8'hEA;

    8'hf8: out <= 8'hA0;

    8'hf9: out <= 8'h7F;

    8'hfa: out <= 8'h1D;

    8'hfb: out <= 8'h52;

    8'hfc: out <= 8'hF9;

    8'hfd: out <= 8'h96;

    8'hfe: out <= 8'hB4;

    8'hff: out <= 8'h8B;

    endcase
endmodule



module invS (clk, in, out);
    input clk;
    input [7:0] in;
    output reg [7:0] out;

    always @ (posedge clk)
    case (in)
		8'h00: out <= 8'h10;

		8'h01: out <= 8'h00;

		8'h02: out <= 8'hE0;

		8'h03: out <= 8'h90;

		8'h04: out <= 8'hB0;

		8'h05: out <= 8'hD0;

		8'h06: out <= 8'h60;

		8'h07: out <= 8'h70;

		8'h08: out <= 8'h20;

		8'h09: out <= 8'hF0;

		8'h0a: out <= 8'h50;

		8'h0b: out <= 8'hC0;

		8'h0c: out <= 8'h40;

		8'h0d: out <= 8'hA0;

		8'h0e: out <= 8'h80;

		8'h0f: out <= 8'h30;

		8'h10: out <= 8'h11;

		8'h11: out <= 8'h01;

		8'h12: out <= 8'hDE;

		8'h13: out <= 8'hB9;

		8'h14: out <= 8'hEB;

		8'h15: out <= 8'h9D;

		8'h16: out <= 8'h76;

		8'h17: out <= 8'h67;

		8'h18: out <= 8'h52;

		8'h19: out <= 8'hCF;

		8'h1a: out <= 8'h35;

		8'h1b: out <= 8'h8C;

		8'h1c: out <= 8'h24;

		8'h1d: out <= 8'hFA;

		8'h1e: out <= 8'hA8;

		8'h1f: out <= 8'h43;

 		8'h20: out <= 8'hDB;

		8'h21: out <= 8'h09;

		8'h22: out <= 8'hE8;

		8'h23: out <= 8'h6C;

		8'h24: out <= 8'hA9;

		8'h25: out <= 8'hF6;

		8'h26: out <= 8'h5F;

		8'h27: out <= 8'h84;

		8'h28: out <= 8'hC5;

		8'h29: out <= 8'h33;

		8'h2a: out <= 8'h41;

		8'h2b: out <= 8'h2D;

		8'h2c: out <= 8'h9A;

		8'h2d: out <= 8'h72;

		8'h2e: out <= 8'hB7;

		8'h2f: out <= 8'h1E;

		8'h30: out <= 8'hBD;
		8'h31: out <= 8'h0E;
		8'h32: out <= 8'h6A;
		8'h33: out <= 8'h9F;
		8'h34: out <= 8'h86;
		8'h35: out <= 8'hCE;
		8'h36: out <= 8'h48;
		8'h37: out <= 8'hF5;
		8'h38: out <= 8'h19;
		8'h39: out <= 8'hD7;
		8'h3a: out <= 8'hEC;
		8'h3b: out <= 8'h73;
		8'h3c: out <= 8'h51;
		8'h3d: out <= 8'h3B;
		8'h3e: out <= 8'h22;
		8'h3f: out <= 8'hA4;

		8'h40: out <= 8'hE9;
		8'h41: out <= 8'h0D;
		8'h42: out <= 8'hA7;
		8'h43: out <= 8'h8D;
		8'h44: out <= 8'hBC;
		8'h45: out <= 8'h7F;
		8'h46: out <= 8'hC3;
		8'h47: out <= 8'h2A;
		8'h48: out <= 8'h31;
		8'h49: out <= 8'h4E;
		8'h4a: out <= 8'h1B;
		8'h4b: out <= 8'h96;
		8'h4c: out <= 8'hF2;
		8'h4d: out <= 8'h55;
		8'h4e: out <= 8'h64;
		8'h4f: out <= 8'hD8;

		8'h50: out <= 8'h9E;
		8'h51: out <= 8'h0B;
		8'h52: out <= 8'hFB;
		8'h53: out <= 8'hC7;
		8'h54: out <= 8'h78;
		8'h55: out <= 8'hDA;
		8'h56: out <= 8'hA2;
		8'h57: out <= 8'h3C;
		8'h58: out <= 8'hBF;
		8'h59: out <= 8'h65;
		8'h5a: out <= 8'h83;
		8'h5b: out <= 8'h44;
		8'h5c: out <= 8'h1D;
		8'h5d: out <= 8'hE6;
		8'h5e: out <= 8'h59;
		8'h5f: out <= 8'h21;

		8'h60: out <= 8'h66;
		8'h61: out <= 8'h07;
		8'h62: out <= 8'h82;
		8'h63: out <= 8'hF3;
		8'h64: out <= 8'h2F;
		8'h65: out <= 8'h38;
		8'h66: out <= 8'h17;
		8'h67: out <= 8'h71;
		8'h68: out <= 8'hDC;
		8'h69: out <= 8'hE4;
		8'h6a: out <= 8'hAD;
		8'h6b: out <= 8'h5E;
		8'h6c: out <= 8'hCB;
		8'h6d: out <= 8'h49;
		8'h6e: out <= 8'h95;
		8'h6f: out <= 8'hBA;

		8'h70: out <= 8'h77;
		8'h71: out <= 8'h06;
		8'h72: out <= 8'h5C;
		8'h73: out <= 8'h4A;
		8'h74: out <= 8'hC4;
		8'h75: out <= 8'hA5;
		8'h76: out <= 8'h61;
		8'h77: out <= 8'h16;
		8'h78: out <= 8'h8E;
		8'h79: out <= 8'h2B;
		8'h7a: out <= 8'h98;
		8'h7b: out <= 8'hD2;
		8'h7c: out <= 8'hEF;
		8'h7d: out <= 8'hB3;
		8'h7e: out <= 8'h3D;
		8'h7f: out <= 8'hF9;

		8'h80: out <= 8'hAC;
		8'h81: out <= 8'h0F;
		8'h82: out <= 8'hB4;
		8'h83: out <= 8'h26;
		8'h84: out <= 8'h6D;
		8'h85: out <= 8'h53;
		8'h86: out <= 8'h3E;
		8'h87: out <= 8'h92;
		8'h88: out <= 8'h4B;
		8'h89: out <= 8'h18;
		8'h8a: out <= 8'hD9;
		8'h8b: out <= 8'hFF;
		8'h8c: out <= 8'h75;
		8'h8d: out <= 8'hC1;
		8'h8e: out <= 8'h8A;
		8'h8f: out <= 8'hE7;

		8'h90: out <= 8'h45;
		8'h91: out <= 8'h02;
		8'h92: out <= 8'h13;
		8'h93: out <= 8'hAB;
		8'h94: out <= 8'hD1;
		8'h95: out <= 8'h2C;
		8'h96: out <= 8'hFD;
		8'h97: out <= 8'hB8;
		8'h98: out <= 8'h7A;
		8'h99: out <= 8'h56;
		8'h9a: out <= 8'hC2;
		8'h9b: out <= 8'h69;
		8'h9c: out <= 8'h87;
		8'h9d: out <= 8'h94;
		8'h9e: out <= 8'hEE;
		8'h9f: out <= 8'h3F;

		8'ha0: out <= 8'hF8;
		8'ha1: out <= 8'h0C;
		8'ha2: out <= 8'h79;
		8'ha3: out <= 8'h34;
		8'ha4: out <= 8'h57;
		8'ha5: out <= 8'hE2;
		8'ha6: out <= 8'hB5;
		8'ha7: out <= 8'h4D;
		8'ha8: out <= 8'h63;
		8'ha9: out <= 8'h81;
		8'haa: out <= 8'h2E;
		8'hab: out <= 8'h1A;
		8'hac: out <= 8'hD6;
		8'had: out <= 8'hAF;
		8'hae: out <= 8'hCC;
		8'haf: out <= 8'h9B;

		8'hb0: out <= 8'h23;
		8'hb1: out <= 8'h05;
		8'hb2: out <= 8'h91;
		8'hb3: out <= 8'h58;
		8'hb4: out <= 8'hFE;
		8'hb5: out <= 8'h14;
		8'hb6: out <= 8'hEA;
		8'hb7: out <= 8'hC9;
		8'hb8: out <= 8'hA6;
		8'hb9: out <= 8'hB2;
		8'hba: out <= 8'h6F;
		8'hbb: out <= 8'h37;
		8'hbc: out <= 8'h4C;
		8'hbd: out <= 8'hDD;
		8'hbe: out <= 8'h7B;
		8'hbf: out <= 8'h85;

		8'hc0: out <= 8'h8F;
		8'hc1: out <= 8'h0A;
		8'hc2: out <= 8'h25;
		8'hc3: out <= 8'h7E;
		8'hc4: out <= 8'h93;
		8'hc5: out <= 8'h47;
		8'hc6: out <= 8'hD4;
		8'hc7: out <= 8'h5B;
		8'hc8: out <= 8'hED;
		8'hc9: out <= 8'hAA;
		8'hca: out <= 8'hB6;
		8'hcb: out <= 8'hC8;
		8'hcc: out <= 8'h39;
		8'hcd: out <= 8'h1C;
		8'hce: out <= 8'hF1;
		8'hcf: out <= 8'h62;

		8'hd0: out <= 8'h32;
		8'hd1: out <= 8'h04;
		8'hd2: out <= 8'h4F;
		8'hd3: out <= 8'hE1;
		8'hd4: out <= 8'h15;
		8'hd5: out <= 8'h89;
		8'hd6: out <= 8'h9C;
		8'hd7: out <= 8'hAE;
		8'hd8: out <= 8'hF4;
		8'hd9: out <= 8'h7D;
		8'hda: out <= 8'h5A;
		8'hdb: out <= 8'hBB;
		8'hdc: out <= 8'h68;
		8'hdd: out <= 8'h27;
		8'hde: out <= 8'hD3;
		8'hdf: out <= 8'hC6;

		8'he0: out <= 8'h54;
		8'he1: out <= 8'h03;
		8'he2: out <= 8'hCD;
		8'he3: out <= 8'h12;
		8'he4: out <= 8'h3A;
		8'he5: out <= 8'hB1;
		8'he6: out <= 8'h8B;
		8'he7: out <= 8'hDF;
		8'he8: out <= 8'h28;
		8'he9: out <= 8'h99;
		8'hea: out <= 8'hF7;
		8'heb: out <= 8'hE5;
		8'hec: out <= 8'hA3;
		8'hed: out <= 8'h6E;
		8'hee: out <= 8'h46;
		8'hef: out <= 8'h7C;

		8'hf0: out <= 8'hCA;
		8'hf1: out <= 8'h08;
		8'hf2: out <= 8'h36;
		8'hf3: out <= 8'hD5;
		8'hf4: out <= 8'h42;
		8'hf5: out <= 8'h6B;
		8'hf6: out <= 8'h29;
		8'hf7: out <= 8'hE3;
		8'hf8: out <= 8'h97;
		8'hf9: out <= 8'hFC;
		8'hfa: out <= 8'h74;
		8'hfb: out <= 8'hA1;
		8'hfc: out <= 8'hBE;
		8'hfd: out <= 8'h88;
		8'hfe: out <= 8'h1F;
		8'hff: out <= 8'h5D;

    endcase
endmodule


module MKDS_128_256_encrypt(clk, reset, state, data_start, data_valid, key, key_expand_start, key_expand_valid, out, keylen);
    input          clk;
	 input 			 reset;
    input  [127:0] state;
    input [1:0] keylen;
	 input  			 data_start;
	 output		    data_valid;
	 input  [255:0] key;
	 input key_expand_start;
	 output key_expand_valid;
    output [127:0] out;

	 wire   [255:0] round_key;
	 wire	  [3:0]  key_addr;

	key_expand
		key_expand_inst (clk, reset, key, key_expand_start, key_expand_valid, key_addr, round_key, keylen);

	round_encrypt
		round_encrypt_inst (clk, reset, key_addr, round_key, state, data_start, out, data_valid, keylen);



endmodule

module MKDS_128_256_decrypt(clk, reset, state, data_start, data_valid, key, key_expand_start, key_expand_valid, out, keylen);
    input          clk;
	 input 			 reset;
    input  [127:0] state;
    input [1:0] keylen;
	 input  			 data_start;
	 output		    data_valid;
	 input  [255:0] key;
	 input key_expand_start;
	 output key_expand_valid;
    output [127:0] out;

	 wire   [255:0] round_key;
	 wire	  [3:0]  key_addr;

	key_expand
		key_expand_inst (clk, reset, key, key_expand_start, key_expand_valid, key_addr, round_key, keylen);

	round_decrypt
		round_decrypt_inst (clk, reset, key_addr, round_key, state, data_start, out, data_valid, keylen);



endmodule

module round_encrypt (clk, reset, key_addr, round_key, data, data_start, out, data_valid, keylen);
    input clk;
	 input reset;
	 input [1:0] keylen; //keysize 0: 128, 1: 192, 2: 256 bit
	 output reg [3:0] key_addr;
	 input [255:0] round_key;
	 input [127:0] data;
	 input  data_start;
	 output [127:0] out;
	 output reg data_valid;

	 localparam NUM_STATE = 6;

	 localparam ROUND_IDLE 				= 0;
	 localparam ROUND_1_WAIT 			= 1;
	 localparam ROUND_1_WAIT_1 			= 2;
	 localparam ROUND_1_WAIT_2 			= 3;
	 localparam ROUND_1 				= 4;
	 localparam ROUND_2_WAIT 			= 5;
	 localparam ROUND_2_WAIT_1 			= 6;
	 localparam ROUND_2 				= 7;
	 localparam ROUND_3_WAIT 			= 8;
	 localparam ROUND_3_WAIT_1 			= 9;
	 localparam ROUND_3 				= 10;
	 localparam ROUND_4_WAIT 			= 11;
	 localparam ROUND_4_WAIT_1 			= 12;
	 localparam ROUND_4 				= 13;
 	 localparam ROUND_5_WAIT 			= 14;
	 localparam ROUND_5_WAIT_1 			= 15;
	 localparam ROUND_5 				= 16;
 	 localparam ROUND_6_WAIT 			= 17;
     localparam ROUND_6_WAIT_1          = 18;
     localparam ROUND_6                 = 19;
  	 localparam ROUND_7_WAIT 			= 20;
     localparam ROUND_7_WAIT_1          = 21;
     localparam ROUND_7                 = 22;
  	 localparam ROUND_8_WAIT 			= 23;
     localparam ROUND_8_WAIT_1          = 24;
     localparam ROUND_8                 = 25;
 	 localparam DONE_WAIT 				= 26;
	 localparam DONE_WAIT_1 			= 27;
	 localparam DONE 					= 28;


     reg [NUM_STATE-1 :0]     state, state_next;
	 reg [127:0] data_in, data_in_next;
	 reg [255:0] key_in, key_in_next;
	 wire [127:0] data_out, data_out_final;



    F
         F_ROUND (clk, data_in, key_in[255:128], key_in[127:0], data_out);

   assign out = data_out ^ round_key[255:128];


    always@(*) begin
      state_next = state;
		data_in_next = data_in;
		key_in_next = key_in;

		key_addr = 0;

		data_valid = 0;

      case(state)
        ROUND_IDLE: begin
           if(data_start) begin
					data_in_next = data;
					key_addr = 0;
					state_next = ROUND_1_WAIT;
           end
        end
        ROUND_1_WAIT: begin
				key_in_next = round_key;
				state_next = ROUND_1_WAIT_1;
        end
        ROUND_1_WAIT_1: begin
				state_next = ROUND_1_WAIT_2;
        end
        ROUND_1_WAIT_2: begin
				key_addr = 1;
				state_next = ROUND_1;
        end
        ROUND_1: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_2_WAIT;
        end
        ROUND_2_WAIT: begin
				state_next = ROUND_2_WAIT_1;
        end
        ROUND_2_WAIT_1: begin
				key_addr = 2;
				state_next = ROUND_2;
        end
        ROUND_2: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_3_WAIT;
        end
        ROUND_3_WAIT: begin
				state_next = ROUND_3_WAIT_1;
        end
        ROUND_3_WAIT_1: begin
				key_addr = 3;
				state_next = ROUND_3;
        end
        ROUND_3: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_4_WAIT;
        end
        ROUND_4_WAIT: begin
				state_next = ROUND_4_WAIT_1;
        end
        ROUND_4_WAIT_1: begin
				key_addr = 4;
				state_next = ROUND_4;
        end
        ROUND_4: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_5_WAIT;
        end
        ROUND_5_WAIT: begin
				state_next = ROUND_5_WAIT_1;
        end
        ROUND_5_WAIT_1: begin
				key_addr = 5;
				state_next = ROUND_5;
        end
        ROUND_5: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_6_WAIT;
        end
        ROUND_6_WAIT: begin
                state_next = ROUND_6_WAIT_1;
        end
        ROUND_6_WAIT_1: begin
                key_addr = 6;
                state_next = ROUND_6;
        end
        ROUND_6: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 0) //128
                       state_next = DONE_WAIT;
                    else
                       state_next = ROUND_7_WAIT;
        end

        ROUND_7_WAIT: begin
                state_next = ROUND_7_WAIT_1;
        end
        ROUND_7_WAIT_1: begin
                key_addr = 7;
                state_next = ROUND_7;
        end
        ROUND_7: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 1) //192
                        state_next = DONE_WAIT; //ROUND_8_WAIT
                    else
                        state_next = ROUND_8_WAIT;
        end

        ROUND_8_WAIT: begin
                state_next = ROUND_8_WAIT_1;
        end
        ROUND_8_WAIT_1: begin
                key_addr = 8;
                state_next = ROUND_8;
        end
        ROUND_8: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 2) //256
                        state_next = DONE_WAIT;

        end
        DONE_WAIT: begin
				state_next = DONE_WAIT_1;
        end
        DONE_WAIT_1: begin
				if(keylen == 2) key_addr = 9; //9
                else if (keylen == 1) key_addr = 8; //8
                else if (keylen == 0) key_addr = 7; //7
				state_next = DONE;
        end
        DONE: begin
				data_valid = 1;

				state_next = ROUND_IDLE;
        end


		endcase


	 end

	   always @(posedge clk) begin
      if(reset) begin
         state <= ROUND_IDLE;
	      data_in <= 0;
	      key_in <= 0;

		end
		else begin
			data_in <= data_in_next;
			key_in <= key_in_next;
			state	<= state_next;
		end

   end


endmodule



module round_decrypt (clk, reset, key_addr, round_key, data, data_start, out, data_valid, keylen);
    input clk;
	 input reset;
	 input [1:0] keylen; //keysize 0: 128, 1: 192, 2: 256 bit
	 output reg [3:0] key_addr;
	 input [255:0] round_key;
	 input [127:0] data;
	 input  data_start;
	 output [127:0] out;
	 output reg data_valid;

	 localparam NUM_STATE = 6;

	 localparam ROUND_IDLE 				= 0;
	 localparam ROUND_1_WAIT 			= 1;
	 localparam ROUND_1_WAIT_1 			= 2;
	 localparam ROUND_1_WAIT_2 			= 3;
	 localparam ROUND_1 				= 4;
	 localparam ROUND_2_WAIT 			= 5;
	 localparam ROUND_2_WAIT_1 			= 6;
	 localparam ROUND_2 				= 7;
	 localparam ROUND_3_WAIT 			= 8;
	 localparam ROUND_3_WAIT_1 			= 9;
	 localparam ROUND_3 				= 10;
	 localparam ROUND_4_WAIT 			= 11;
	 localparam ROUND_4_WAIT_1 			= 12;
	 localparam ROUND_4 				= 13;
 	 localparam ROUND_5_WAIT 			= 14;
	 localparam ROUND_5_WAIT_1 			= 15;
	 localparam ROUND_5 				= 16;
 	 localparam ROUND_6_WAIT 			= 17;
     localparam ROUND_6_WAIT_1          = 18;
     localparam ROUND_6                 = 19;
  	 localparam ROUND_7_WAIT 			= 20;
     localparam ROUND_7_WAIT_1          = 21;
     localparam ROUND_7                 = 22;
  	 localparam ROUND_8_WAIT 			= 23;
     localparam ROUND_8_WAIT_1          = 24;
     localparam ROUND_8                 = 25;
 	 localparam DONE_WAIT 				= 26;
	 localparam DONE_WAIT_1 			= 27;
	 localparam DONE 					= 28;


     reg [NUM_STATE-1 :0]     state, state_next;
	 reg [127:0] data_in, data_in_next;
	 reg [255:0] key_in, key_in_next;
	 wire [127:0] data_out, data_out_final;



    invF
         invF_ROUND (clk, data_in, key_in[255:128], key_in[127:0], data_out);

   assign out = data_out;


    always@(*) begin
      state_next = state;
		data_in_next = data_in;
		key_in_next = key_in;

		key_addr = 0;

		data_valid = 0;

      case(state)
        ROUND_IDLE: begin
           if(data_start) begin
					data_in_next = data;
					key_addr = 9;
					state_next = ROUND_1_WAIT;
           end
        end
        ROUND_1_WAIT: begin
                data_in_next = data_in ^ round_key[255:128];
                key_addr = 8;
				state_next = ROUND_1_WAIT_1;
        end
        ROUND_1_WAIT_1: begin
        		key_in_next = round_key;
				state_next = ROUND_1_WAIT_2;
        end
        ROUND_1_WAIT_2: begin
				key_addr = 7;
				state_next = ROUND_1;
        end
        ROUND_1: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_2_WAIT;
        end
        ROUND_2_WAIT: begin
				state_next = ROUND_2_WAIT_1;
        end
        ROUND_2_WAIT_1: begin
				key_addr = 6;
				state_next = ROUND_2;
        end
        ROUND_2: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_3_WAIT;
        end
        ROUND_3_WAIT: begin
				state_next = ROUND_3_WAIT_1;
        end
        ROUND_3_WAIT_1: begin
				key_addr = 5;
				state_next = ROUND_3;
        end
        ROUND_3: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_4_WAIT;
        end
        ROUND_4_WAIT: begin
				state_next = ROUND_4_WAIT_1;
        end
        ROUND_4_WAIT_1: begin
				key_addr = 4;
				state_next = ROUND_4;
        end
        ROUND_4: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_5_WAIT;
        end
        ROUND_5_WAIT: begin
				state_next = ROUND_5_WAIT_1;
        end
        ROUND_5_WAIT_1: begin
				key_addr = 3;
				state_next = ROUND_5;
        end
        ROUND_5: begin
					data_in_next = data_out;
					key_in_next = round_key;
					state_next = ROUND_6_WAIT;
        end
        ROUND_6_WAIT: begin
                state_next = ROUND_6_WAIT_1;
        end
        ROUND_6_WAIT_1: begin
                key_addr = 2;
                state_next = ROUND_6;
        end
        ROUND_6: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 0) //128
                        state_next = DONE_WAIT;
                    else
                        state_next = ROUND_7_WAIT;
        end

        ROUND_7_WAIT: begin
                state_next = ROUND_7_WAIT_1;
        end
        ROUND_7_WAIT_1: begin
                key_addr = 1;
                state_next = ROUND_7;
        end
        ROUND_7: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 1) //192
                        state_next = DONE_WAIT; //ROUND_8_WAIT
                    else
                        state_next = ROUND_8_WAIT;
        end

        ROUND_8_WAIT: begin
                state_next = ROUND_8_WAIT_1;
        end
        ROUND_8_WAIT_1: begin
                key_addr = 0;
                state_next = ROUND_8;
        end
        ROUND_8: begin
                    data_in_next = data_out;
                    key_in_next = round_key;
                    if(keylen == 2) //256
                        state_next = DONE_WAIT; //ROUND_8_WAIT
        end
        DONE_WAIT: begin
				state_next = DONE_WAIT_1;
        end
        DONE_WAIT_1: begin
				state_next = DONE;
        end
        DONE: begin
				data_valid = 1;

				state_next = ROUND_IDLE;
        end


		endcase


	 end

	   always @(posedge clk) begin
      if(reset) begin
         state <= ROUND_IDLE;
	      data_in <= 0;
	      key_in <= 0;

		end
		else begin
			data_in <= data_in_next;
			key_in <= key_in_next;
			state	<= state_next;
		end

   end


endmodule



module key_expand (clk, reset, key, start, valid, key_addr, round_key, keylen);
    input clk;
	 input reset;
	  input [1:0] keylen; //keysize 0: 128, 1: 192, 2: 256 bit
    input  [255:0] key;
	 input  start;
	 output reg valid;
	 input [3:0] key_addr;
    output reg [255:0] round_key;

    localparam KEY_EXPAND_IDLE = 0;
    localparam KEY_EXPAND_K1        = 1;
    localparam KEY_EXPAND_K2        = 2;
    localparam KEY_EXPAND_K3        = 3;
    localparam KEY_EXPAND_K4        = 4;
    localparam KEY_EXPAND_K5        = 5;
    localparam KEY_EXPAND_K6        = 6;
    localparam KEY_EXPAND_K7        = 7;
    localparam KEY_EXPAND_K8        = 8;
    localparam KEY_EXPAND_K9        = 9;
    localparam KEY_EXPAND_END       = 10;

    reg [3:0]     state, state_next;
	 reg [127:0] key_in_left, key_in_left_next;
	 reg [127:0] key_in_right, key_in_right_next;
	 reg [7:0] key_const_in, key_const_in_next;
    wire   [127:0] fl, fr;
	 reg 	k1_valid, k2_valid, k3_valid, k4_valid, k5_valid, k6_valid, k7_valid, k8_valid, k9_valid, k10_valid;


    reg [255:0]      lut[15:0] ;
    reg [3:0]        wr_addr;
    reg         		wr_en;
    reg [255:0]		wr_data_sel;
	 reg 					valid_reg;

	 wire [3:0] 		addr;

   reg [4:0]         reset_count;
   reg               lut_state;
   reg [2:0]        cnt, cnt_next;

    assign addr = (wr_en) ? wr_addr : key_addr;

 	 F_key
		f_key1 (clk, key_in_left, key_in_right, key_const_in, fl, fr);



	 always @(posedge clk) begin
      if(reset) begin
			valid <= 0;

         wr_en <= 0;
	      wr_addr <= 0;
	      wr_data_sel <= 0;
			lut_state <= 0;
			reset_count <= 0;
		end
		else begin
         if (lut_state == 0) begin
            if(reset_count == 16) begin
               lut_state  <= 1;
               wr_en <= 1'b0;
            end
            else begin
               reset_count      <= reset_count + 1'b1;
               wr_en            <= 1'b1;
               wr_addr      	  <= reset_count[3:0];
               wr_data_sel      <= 0;
            end
         end
			else if (lut_state == 1) begin

					if (valid_reg) begin
						valid <= 1;
					end

					wr_en <= k1_valid || k2_valid || k3_valid || k4_valid ||
								k5_valid || k6_valid || k7_valid || k8_valid || k9_valid || k10_valid;


					if (start) begin
                        valid <= 0;
                    end
					else if (k1_valid) begin
						wr_data_sel[255:128] <= key_in_left;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 0;
					end
					else if (k2_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 1;
					end
					else if (k3_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 2;
					end
					else if (k4_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 3;
					end
					else if (k5_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 4;
					end
					else if (k6_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 5;
					end
					else if (k7_valid) begin
						wr_data_sel[255:128] <= key_in_right;
						wr_data_sel[127:0] <= fl;
						wr_addr <= 6;
					end
					else if (k8_valid) begin
						wr_data_sel[255:128] <= key_in_right;
                        wr_data_sel[127:0] <= fl;
                        wr_addr <= 7;
                    end
					else if (k9_valid) begin
                        wr_data_sel[255:128] <= key_in_right;
                        wr_data_sel[127:0] <= fl;
                        wr_addr <= 8;
                    end
					else if (k10_valid) begin
                        wr_data_sel[255:128] <= key_in_right;
                        wr_data_sel[127:0] <= 128'h0;
                        wr_addr <= 9;
                    end
			end

		end
	 end




    always @ (posedge clk) begin
			if (reset) begin
				round_key <= 0;
			end
			else begin
				if (wr_en) begin
				 lut [addr] <= wr_data_sel;
				end

				round_key <= lut [addr];
			end
	 end


    always@(*) begin
      state_next = state;
      cnt_next = cnt;
		key_in_left_next = key_in_left;
		key_in_right_next = key_in_right;
		key_const_in_next = key_const_in;

		k1_valid = 0;
		k2_valid = 0;
		k3_valid = 0;
		k4_valid = 0;
		k5_valid = 0;
		k6_valid = 0;
		k7_valid = 0;
		k8_valid = 0;
		k9_valid = 0;
		k10_valid = 0;
		valid_reg = 0;

      case(state)
        KEY_EXPAND_IDLE: begin
           if(start) begin
				  if(keylen == 2) begin //keysize = 256
                           key_in_left_next = key[255:128];

                           key_in_right_next = key[127:0];

                   end
                   else if(keylen == 1) begin //keysize = 192
                           key_in_left_next = key[191:64];

                           key_in_right_next = {key[63:0],~key[127: 64]};

                   end
                   else if(keylen == 0 ) begin //keysize = 128
                           key_in_left_next = key[127:0];

                           key_in_right_next = {key[127:0],~key[127:0]};

                   end
                   key_const_in_next = 8'h1;
				   state_next = KEY_EXPAND_K1;
           end
        end
        KEY_EXPAND_K1: begin
                    if (cnt == 4) begin
                        k1_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'h3;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K2;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K2: begin
                    if (cnt == 4) begin
                        k2_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'h5;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K3;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K3: begin
                    if (cnt == 4) begin
                        k3_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'h7;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K4;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K4: begin
                    if (cnt == 4) begin
                        k4_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'h9;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K5;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K5: begin
                    if (cnt == 4) begin
                        k5_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'hB;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K6;
                    end
                    else
                       cnt_next = cnt + 1;

        end
        KEY_EXPAND_K6: begin
                    if (cnt == 4) begin
                        k6_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'hD;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K7;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K7: begin
                    if (cnt == 4) begin
                        k7_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'hF;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K8;
                    end
                    else
                       cnt_next = cnt + 1;

        end
        KEY_EXPAND_K8: begin
                    if (cnt == 4) begin
                        k8_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_const_in_next = 8'h11;
                        key_in_right_next = fr;
                        state_next = KEY_EXPAND_K9;
                    end
                    else
                       cnt_next = cnt + 1;

        end

        KEY_EXPAND_K9: begin
                    if (cnt == 4) begin
                        k9_valid = 1;
                        cnt_next = 0;
                        key_in_left_next = fl;
                        key_in_right_next = fr;
                        valid_reg = 1;
                        state_next = KEY_EXPAND_END;
                    end
                    else
                       cnt_next = cnt + 1;

        end
        KEY_EXPAND_END: begin
                  k10_valid = 1;
                  state_next = KEY_EXPAND_IDLE;
        end

      endcase
   end

   always @(posedge clk) begin
      if(reset) begin
         state <= KEY_EXPAND_IDLE;
			key_in_left <= 128'h0;
			key_in_right <= 128'h0;
			key_const_in <= 8'h0;
			cnt <= 0;
      end
		else begin
			state <= state_next;
			key_in_left <= key_in_left_next;
			key_in_right <= key_in_right_next;
			key_const_in <= key_const_in_next;
	        cnt <= cnt_next;
		end
   end



endmodule


module F_key (clk, key_left, key_right, const, out_left, out_right);
    input clk;
    input  [127:0] key_left;
	 input  [127:0] key_right;
	 input  [7:0] const;

    output [127:0] out_left;
    output [127:0] out_right;


	 wire  [127:0] tmpC;
	 wire [127:0] CL, CR;


	 wire [127:0] tmp1, tmp2, tmp3, tmp4;

	 assign tmpC = 128'h0;
	 assign CL = 128'h9302ee911a2ad98cad13e7948ad8b3b2 ^ {120'h0, const};
	 assign CR = 128'hd4da00f33f11fd8822166bb9cd187c55 ^ {120'h0, const + 1};

	 F
		 f1 (clk, key_left, CL, tmpC, tmp1),
		 f2 (clk, tmp1, tmpC, tmpC, tmp2);

	 F
         f3 (clk, key_right, CR, tmpC, tmp3),
         f4 (clk, tmp3, tmpC, tmpC, tmp4);


	 assign out_right = tmp4 ^ tmp2;
	 assign out_left = tmp4;


endmodule



module F (clk, in, key1, key2, out);
    input clk;
    input  [127:0] in;
	 input  [127:0] key1;
	 input  [127:0] key2;
    output [127:0] out;

	 wire [127:0] b,b1,b2,b3;

	 SubCells
        s1 (in ^ key1, b),
		  s2 (b1 ^ key2, b2);

	 Mix_column
		  mix1 (b, b1);

	 XWord
		  xword (b2, b3);

	 assign out = b3;


endmodule

module invF (clk, in, key1, key2, out);
    input clk;
    input  [127:0] in;
	 input  [127:0] key1;
	 input  [127:0] key2;
    output [127:0] out;

	 wire [127:0] b,b1,b2,b3;


     XWord
          invxword (in, b);

	 InvSubcells
        invs1 (b, b1),
		 invs2 (b2, b3);

	 InvMix_column
		  invmix1 (b1 ^ key2, b2);


	 assign out = b3 ^ key1;


endmodule

// gf_mul_by_x.v
// Nhân m?t ph?n t? 128-bit T v?i x trong GF(2^128)
//   T_next = (T << 1) ? (T[127] ? 0x87 : 0)

module gf_mul_by_x (
    input  wire [127:0] T,        // tweak ??u vào, big-endian: T[127] là MSB, T[0] LSB
    output wire [127:0] T_next    // k?t qu?
);

    // D?ch trái 1 bit (b? MSB, thêm 0 vào LSB)
    wire [127:0] shifted = T << 1;

    // N?u MSB ban ??u = 1, thì XOR h?ng s? 0x87 vào byte th?p nh?t (bit [7:0])
    wire [127:0] reduction = {120'd0, 8'h87} & {128{T[127]}};

    // K?t qu? cu?i cùng
    assign T_next = shifted ^ reduction;

endmodule

// gf_mul_by_x_lut32.v
`timescale 1ns/1ps

module gf_mul_by_x_lut32 (
    input  wire         clk,
    input  wire         rst_n,    // active low reset
    input  wire         start,    // start calculating
    input  wire [127:0] T_in,     // giá tr? T ban ??u
    input  wire  [4:0]  j,        // index truy xu?t (0..31)
    output wire [127:0] T_out,    // k?t qu? LUT[j]
    output reg          busy,     // ?ang tính
    output reg          done      // ?ã tính xong 32 giá tr?
);

    // h?ng s? reduction = 0x87 ? byte th?p nh?t
    localparam [127:0] REDUCTION = 128'h00000000000000000000000000000087;

    // b? ??m vòng tính
    reg [5:0] count;
    // LUT l?u 32 giá tr?
    reg [127:0] lut [0:31];

    // tmp gi? giá tr? hi?n t?i ?? nhân
    reg [127:0] tmp;

    // combinational logic tính b??c nhân Galois
    wire msb = tmp[127];
    wire [127:0] shifted   = tmp << 1;
    wire [127:0] reduced   = shifted ^ (msb ? REDUCTION : 128'd0);

    // ??c LUT
    assign T_out = lut[j];

    // state machine
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy  <= 1'b0;
            done  <= 1'b0;
            count <= 6'd0;
            tmp   <= 128'd0;
        end else begin
            if (start && !busy) begin
                // kh?i ??ng
                busy      <= 1'b1;
                done      <= 1'b0;
                count     <= 6'd0;
                tmp       <= T_in;
                lut[0]    <= T_in;      // l?u T_in vào ô 0
            end
            else if (busy) begin
                // ?ang tính: vòng th? count+1
                tmp          <= reduced;
                lut[count+1] <= reduced;
                count        <= count + 6'd1;

                if (count == 6'd31) begin
                    // ?ã l?u ?? 32 entry (0..31)
                    busy <= 1'b0;
                    done <= 1'b1;
                end
            end
        end
    end

endmodule



`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 05/15/2024 11:55:27 PM
// Design Name:
// Module Name: xts_enc
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


module mkv( //include key expand, encrypt, decrypt
        input clk,
        input reset,

        input enc0_dec1, //enc = 0, dec = 1
        input [1:0] keylen,
        input ecb,

        input [255:0] key1,
        input [255:0] key2,
        input key1_start, key2_start,
        //input data_ivalid,
        input idata_key1_valid,
        input [127:0] idata_key1,

        input [4:0] j_block, //block thu j trong 1 sector

        input idata_key2_valid,
        input [127:0] idata_key2,
        //input [24:0] length,
        //input fis_is_data_enc, //=0: bypass; =1:enc/dec

        output reg okey1_ready,okey2_ready,
        output [127:0] odata,
        output reg o_data_valid, //c
        output reg key2_enc_done
        //output busy //not use currently

    );

    reg [127:0] i_sector;

    reg [127:0] idata_enc, idata_dec;
    wire [127:0] odata_enc, odata_dec;

    reg [2:0] a = 3'd2;

    wire key_expand_valid;
    reg key_expand_start;
    reg [255:0] key_enc, key_dec;

    reg data_start;

    wire   [255:0] round_key;

    wire odata_valid_enc, odata_valid_dec;

    wire      [3:0]  key_addr_key_expand, key_addr_enc, key_addr_dec;



    localparam IDLE = 0;

    localparam KEY2_EXPAND_WAIT=1;
    localparam KEY2_EXPAND=2;
    localparam KEY2_EXPAND_DONE=3;
    localparam KEY2_ENCRYPT_WAIT=4;
    localparam KEY2_ENCRYPT=5;

    localparam KEY2_ENCRYPT_DONE=6;
    localparam KEY2_DONE=7;

    localparam KEY1_EXPAND_WAIT=8;
    localparam KEY1_EXPAND=9;
    localparam KEY1_EXPAND_DONE=10;

    localparam KEY1_ENCRYPT_WAIT=11;
    localparam KEY1_ENCRYPT=12;
    localparam KEY1_ENCRYPT_DONE=13;

    localparam KEY1_DECRYPT_WAIT=14;
    localparam KEY1_DECRYPT=15;
    localparam KEY1_DECRYPT_DONE=16;
    localparam KEY1_DONE=17;

    localparam DONE=18;

    reg [10 :0]     state, state_next;

    key_expand  key_expand_inst (
        .clk(clk),
        .reset(reset),
        .key(key_enc),
        .start(key_expand_start),
        .valid(key_expand_valid),
        .key_addr(key_addr_key_expand),
        .round_key(round_key),
        .keylen(keylen)
        );

    round_encrypt   round_encrypt_inst (
        .clk(clk),
        .reset(reset),
        .key_addr(key_addr_enc),
        .round_key(round_key),
        .data(idata_enc),
        .data_start(data_start),
        .out(odata_enc),
        .data_valid(odata_valid_enc),
        .keylen(keylen)
        );

    round_decrypt   round_decrypt_inst (
        .clk(clk),
        .reset(reset),
        .key_addr(key_addr_dec),
        .round_key(round_key),
        .data(idata_dec),
        .data_start(data_start),
        .out(odata_dec),
        .data_valid(odata_valid_dec),
        .keylen(keylen)
        );



 reg key_addr_control; //=1: key_addr_dec; =0: key_addr_enc
 assign key_addr_key_expand = key_addr_control ? key_addr_dec : key_addr_enc;

  reg  [127:0] out_key2_enc;
  wire [127:0] AxOut_key2;
  assign AxOut_key2 = ecb ? 128'd0 : T_out; //chuyen thanh register sau
  reg [127:0] idata_key1_reg, idata_key2_reg;
  reg mul_start;
  reg [127:0] T_in;
  wire [127:0]  T_out;
  wire gmul_busy, gmul_done;



  gf_mul_by_x_lut32 gmul (
          .clk(clk),
          .rst_n(!reset),
          .start(mul_start),
          .T_in(T_in),
          .j(j_block),
          .T_out(T_out),
          .busy(gmul_busy),
          .done(gmul_done)
      );

      always @(posedge clk) begin
          case (state)
              IDLE: begin
                  mul_start <= 0;
              end

              KEY2_ENCRYPT: begin
                  if (odata_valid_enc) begin
                      mul_start <= 1;    // run gmul ở đây
                      T_in      <= odata_enc;
                  end

                  if (mul_start) begin
                      mul_start <= 0;    // thêm dấu chấm phẩy
                  end
              end

              default: begin
                  mul_start <= 0;
                  // có thể reset T_in hoặc để nguyên tuỳ nhu cầu
              end
          endcase
      end



    //test
    reg [127:0] odata_reg;
    assign odata = odata_reg;

    always@(posedge clk) begin

    case(state)
    IDLE: begin
        odata_reg <= 0;
    end
    KEY1_ENCRYPT: begin //for encrypt

        odata_reg<=odata_enc ^ AxOut_key2;


    end
    KEY1_DECRYPT: begin //for decrypt

        odata_reg<=odata_dec ^ AxOut_key2;

    end

    endcase


    end

    always@(*) begin
          state_next = state;
          key_expand_start = 0;
          //okey2_ready = 0;
          //okey1_ready = 0;
          key_enc = 0;
          data_start = 0;
          //key2_enc_done = 0;
          //odata_reg = 0;
          //o_data_valid = 0;
          idata_enc = 0;
          idata_dec = 0;
          key_addr_control = 0; //2 cais nayf
          //out_key2_enc = 0; //2 cais nayf


          case(state)
            IDLE: begin
              if(ecb) begin
                    key2_enc_done = 1;
                    key_addr_control =0;
                    key_enc = key1;
                    key_expand_start = 0;
                    okey2_ready = 0;
                    okey1_ready = 0;
                    data_start = 0;
                    o_data_valid = 0;

                    state_next = KEY2_DONE;
               end
               else if(key2_start) begin
                    //data_in_next = data;
                    //key_addr = 0;
                    key_addr_control =0;
                    key_enc = key2;
                    key_expand_start = 1;
                    okey2_ready = 0;
                    okey1_ready = 0;
                    data_start = 0;
                    key2_enc_done = 0;
                    //odata_reg = 0;
                    o_data_valid = 0;
                    //out_key2_enc = 0;
                    state_next = KEY2_EXPAND_WAIT;
               end



             end
             KEY2_EXPAND_WAIT: begin
                    key_expand_start = 0;
                    state_next = KEY2_EXPAND;

             end
             KEY2_EXPAND: begin
                  if(key_expand_valid) begin

                      okey2_ready = 1;
                      state_next = KEY2_EXPAND_DONE;
                  end
             end
             KEY2_EXPAND_DONE: begin
                  okey2_ready = 1;
                  if(idata_key2_valid) begin
                      idata_enc = idata_key2;
                      data_start =1;

                      state_next = KEY2_ENCRYPT_WAIT;


                  end

             end
             KEY2_ENCRYPT_WAIT: begin
                  data_start =0;
                  key_addr_control = 0;
                  state_next = KEY2_ENCRYPT;
             end
             KEY2_ENCRYPT: begin
                 if(gmul_done) begin
                      key2_enc_done = 1;

                      //out_key2_enc = odata_enc;


                      state_next = KEY2_ENCRYPT_DONE;
                 end
             end
             KEY2_ENCRYPT_DONE: begin

                    state_next = KEY2_DONE;
             end

             KEY2_DONE: begin
                  key2_enc_done = 1;
                  if(key1_start) begin
                      //if(enc0_dec1==0) begin //encrypt
                      key_enc = key1;

                      key_expand_start = 1;

                      okey1_ready = 0;
                      state_next = KEY1_EXPAND_WAIT;
                      //end
                  end


              end
              KEY1_EXPAND_WAIT: begin
                  o_data_valid = 0;
                  key_expand_start = 0;
                  state_next = KEY1_EXPAND;
              end
              KEY1_EXPAND: begin


                  if(key_expand_valid) begin
                      okey1_ready = 1;

                      state_next = KEY1_EXPAND_DONE;
                  end

              end
              KEY1_EXPAND_DONE: begin
                    okey1_ready = 1;

                  if(idata_key1_valid) begin


                      data_start =1;

                      if(enc0_dec1==0) begin
                          key_addr_control = 0;
                          idata_enc = idata_key1 ^ AxOut_key2;
                          state_next = KEY1_ENCRYPT_WAIT;
                      end
                      else begin
                          key_addr_control = 1;
                          idata_dec = idata_key1 ^ AxOut_key2;
                          state_next = KEY1_DECRYPT_WAIT;
                      end
                  end
              end
              KEY1_ENCRYPT_WAIT: begin
                  data_start = 0;
                  key_addr_control = 0;
                  state_next = KEY1_ENCRYPT;
              end
              KEY1_ENCRYPT: begin //for encrypt
                  key_addr_control = 0;
                  if(odata_valid_enc) begin
                      //odata=odata_enc ^ AxOut_key2;
                      o_data_valid=0;
                      state_next= KEY1_DONE;
                  end
              end
              KEY1_DECRYPT_WAIT: begin
                  data_start=0;
                  key_addr_control = 1;

                  state_next=KEY1_DECRYPT;
              end
              KEY1_DECRYPT: begin //for decrypt
                  key_addr_control = 1;
                  if(odata_valid_dec) begin
                      //odata=odata_dec ^ AxOut_key2;
                      o_data_valid=0;
                      state_next=KEY1_DONE;
                  end
              end

              KEY1_DONE: begin
                  o_data_valid=1;
                  state_next=DONE;
              end
              DONE: begin
                  o_data_valid=1;

                  if(key2_start) begin
                        //data_in_next = data;
                        //key_addr = 0;
                        key_enc=key2;
                        key_expand_start=1;
                        okey2_ready=0;
                        okey1_ready=0;
                        data_start=0;
                        key2_enc_done=0;

                        state_next=KEY2_EXPAND_WAIT;
                   end
                    else if(key1_start) begin
                          //if(enc0_dec1==0) begin //encrypt
                              key_enc=key1;

                              key_expand_start=1;
                              okey1_ready=0;
                              state_next=KEY1_EXPAND_WAIT;
                          //end
                      end
                      else if(idata_key1_valid) begin

                          //okey1_ready = 0;
                          data_start=1;

                          if(enc0_dec1==0) begin
                              key_addr_control=0; //can be replaced by enc0_dec1
                              idata_enc=idata_key1 ^ AxOut_key2;
                              state_next=KEY1_ENCRYPT_WAIT;
                          end
                          else begin
                              key_addr_control=1;
                              idata_dec=idata_key1 ^ AxOut_key2;
                              state_next=KEY1_DECRYPT_WAIT;
                          end
                      end


              end

          endcase

     end


  always @(posedge clk)
    begin
        if(reset)  begin
            state <= IDLE;
            //state_next <= IDLE;
            //i_sector <=128'b0;

        end
        else
            begin
                state	<= state_next;

            end
    end



endmodule

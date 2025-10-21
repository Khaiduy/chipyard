`timescale 1ns/1ps

module ascon_top_tb_simple;
  // Parameters
  localparam CLOCK_PERIOD = 10;
  localparam TIMEOUT_CYCLES = 50000;
  localparam [2:0] MODE_XOF  = 3'b000;
  localparam [2:0] MODE_HASH = 3'b001;
  localparam [2:0] MODE_CXOF = 3'b010;
  localparam [2:0] MODE_AEAD = 3'b011;
  localparam [2:0] MODE_HMAC = 3'b100;
  
  // Clock and reset
  reg clk = 0;
  reg rst_n = 1;
  
  // Top module interface
  reg [63:0] config_in;
  reg input_fifo_wr_en;
  reg [63:0] input_fifo_wr_data;
  wire [63:0] output_fifo_rd_data;
  wire output_fifo_rd_valid;
  reg output_fifo_rd_en;
  reg [127:0] key_in;
  reg [127:0] nonce_in;
  reg key_wr_en;
  reg nonce_wr_en;
  wire [12:0] status_out;
  wire [255:0] tag_out;
  
  // Extract status bits for easy access
  wire dut_busy = status_out[0];
  wire dut_done = status_out[1];
  wire dut_tag_valid = status_out[2];
  wire fifo_underflow = status_out[3];
  wire dut_message_phase = status_out[4];
  wire input_fifo_full = status_out[5];
  wire input_fifo_empty = status_out[6];
  wire input_fifo_almost_full = status_out[7];
  wire input_fifo_almost_empty = status_out[8];
  wire output_fifo_full = status_out[9];
  wire output_fifo_empty = status_out[10];
  wire output_fifo_almost_full = status_out[11];
  wire output_fifo_almost_empty = status_out[12];
  
  // Test variables
  integer i, timeout_cnt;
  
  // DUT instantiation
  ascon_top dut (
    .clk(clk),
    .rst_n(rst_n),
    .config_in(config_in),
    .input_fifo_wr_en(input_fifo_wr_en),
    .input_fifo_wr_data(input_fifo_wr_data),
    .output_fifo_rd_data(output_fifo_rd_data),
    .output_fifo_rd_valid(output_fifo_rd_valid),
    .output_fifo_rd_en(output_fifo_rd_en),
    .key_in(key_in),
    .nonce_in(nonce_in),
    .key_wr_en(key_wr_en),
    .nonce_wr_en(nonce_wr_en),
    .status_out(status_out),
    .tag_out(tag_out)
  );
  
  // Clock generation
  always #(CLOCK_PERIOD/2) clk = ~clk;
  
  // Helper task: Wait for operation to complete
  task wait_for_done;
    input integer max_cycles;
    integer wait_cnt;
    begin
      wait_cnt = 0;
      $display("[TB] Waiting for operation to complete (dut_done)...");
      while (!dut_done && wait_cnt < max_cycles) begin
        @(posedge clk);
        wait_cnt = wait_cnt + 1;
      end
      if (dut_done) begin
        $display("[TB] Operation completed after %0d cycles", wait_cnt);
      end else begin
        $display("[TB] ERROR: Timeout waiting for dut_done after %0d cycles", wait_cnt);
      end
    end
  endtask
  
  // Helper task: Wait for tag to be valid and read it
  task wait_for_tag;
    input integer max_cycles;
    output [255:0] captured_tag;
    integer wait_cnt;
    begin
      wait_cnt = 0;
      $display("[TB] Waiting for tag output (dut_tag_valid)...");
      $display("[TB] Initial status: busy=%b, done=%b, tag_valid=%b", dut_busy, dut_done, dut_tag_valid);
      while (!dut_tag_valid && wait_cnt < max_cycles) begin
        @(posedge clk);
        wait_cnt = wait_cnt + 1;
        if (wait_cnt % 1000 == 0) begin
          $display("[TB] ... still waiting (%0d cycles), status: busy=%b, done=%b, tag_valid=%b", 
                   wait_cnt, dut_busy, dut_done, dut_tag_valid);
        end
      end
      if (dut_tag_valid) begin
        captured_tag = tag_out;
        $display("[TB] Tag valid after %0d cycles", wait_cnt);
        $display("[TB] Tag output: %064x", captured_tag);
      end else begin
        $display("[TB] ERROR: Timeout waiting for dut_tag_valid after %0d cycles", wait_cnt);
        $display("[TB] Final status: busy=%b, done=%b, tag_valid=%b", dut_busy, dut_done, dut_tag_valid);
        captured_tag = 256'h0;
      end
    end
  endtask
  
  // Helper task: Wait for tag valid and check against expected value
  task check_tag;
    input [255:0] expected_tag;
    input integer max_cycles;
    reg [255:0] actual_tag;
    begin
      wait_for_tag(max_cycles, actual_tag);
      if (dut_tag_valid) begin
        if (actual_tag == expected_tag) begin
          $display("[TB] ✓ TEST PASSED - Tag matches!");
          $display("[TB]   Expected: %064x", expected_tag);
          $display("[TB]   Got:      %064x", actual_tag);
        end else begin
          $display("[TB] ✗ TEST FAILED - Tag mismatch!");
          $display("[TB]   Expected: %064x", expected_tag);
          $display("[TB]   Got:      %064x", actual_tag);
        end
      end
    end
  endtask
  
  // Helper task: Reset the design
  task reset_design;
    begin
      $display("[TB] Resetting design...");
      rst_n = 0;
      config_in = 0;
      input_fifo_wr_en = 0;
      input_fifo_wr_data = 0;
      output_fifo_rd_en = 0;
      key_in = 0;
      nonce_in = 0;
      key_wr_en = 0;
      nonce_wr_en = 0;
      repeat (5) @(posedge clk);
      rst_n = 1;
      repeat (2) @(posedge clk);
      $display("[TB] Reset complete");
    end
  endtask
  
  initial begin
    $dumpfile("ascon_top_tb.vcd");
    $dumpvars(0, ascon_top_tb_simple);
    
    $display("=== ASCON TOP MODULE TEST ===");
    $display("Testing FSM flow with HMAC operation");
    
    // Initial reset
    reset_design();
    
    // ========================================
    // TEST 1: Small key (< 64 bytes, no hashing)
    // ========================================
    $display("\n========================================");
    $display("TEST 1: HMAC (10-byte key, 18-byte message)");
    $display("========================================");

    // Pack and send config FIRST: mode[2:0], start[3], key_size[13:4], msg_size[63:14]
    $display("[TB] Starting HMAC operation (key=10 bytes, msg=18 bytes)...");
    @(posedge clk);
    config_in = {50'd18, 10'd10, 1'b1, MODE_HMAC};  // msg_size=18, key_size=10, start=1, mode=100
    @(posedge clk);

    // Clear start bit
    config_in = {50'd18, 10'd10, 1'b0, MODE_HMAC};
    
    $display("[TB] Design started, FSM should be waiting for FIFO data...");

    // Now write key to FIFO with 10-cycle gaps: "HelloWorld" (10 bytes = 2 chunks)
    $display("[TB] Writing key chunk 1 to FIFO...");
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h48656c6c6f576f72; // "HelloWor"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    $display("[TB] Waiting 10 cycles...");
    repeat(10) @(posedge clk);
    $display("[TB] Writing key chunk 2 to FIFO...");
    input_fifo_wr_data = 64'h6c64000000000000; // "ld......"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Write message to FIFO with 10-cycle gaps: "This is a test m..." (18 bytes = 3 chunks)
    $display("[TB] Waiting 10 cycles...");
    repeat(10) @(posedge clk);
    $display("[TB] Writing message chunk 1 to FIFO...");
    input_fifo_wr_data = 64'h5468697320697320; // "This is "
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    $display("[TB] Waiting 10 cycles...");
    repeat(10) @(posedge clk);
    $display("[TB] Writing message chunk 2 to FIFO...");
    input_fifo_wr_data = 64'h612074657374206d; // "a test m"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    $display("[TB] Waiting 10 cycles...");
    repeat(10) @(posedge clk);
    $display("[TB] Writing message chunk 3 to FIFO...");
    input_fifo_wr_data = 64'h7367000000000000; // "sg......"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Wait for completion and check result
    $display("[TB] All data written, waiting for HMAC computation...");
    repeat(10) @(posedge clk);  // Give design time to start processing
    check_tag(256'hc853235b0f918cec79e8f0a2ad4efb2b273f98b258a22cb14fa628ce045745be, 10000);
    wait_for_done(1000);
    
    // Wait a bit before next test
    repeat(20) @(posedge clk);
    
    // ========================================
    // TEST 2: Key size > 64 bytes (requires key hashing)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 2: HMAC (74-byte key, 65-byte message)");
    $display("========================================");

    // Start operation
    $display("[TB] Starting HMAC operation (key=74 bytes, msg=65 bytes)...");
    @(posedge clk);
    config_in = {50'd65, 10'd74, 1'b1, MODE_HMAC};  // msg_size=65, key_size=74, start=1, mode=100
    @(posedge clk);

    // Clear start bit
    config_in = {50'd65, 10'd74, 1'b0, MODE_HMAC};
    
    // Write key to FIFO: "This is a very l..." (74 bytes = 10 chunks)
    $display("[TB] Writing key to FIFO...");
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5468697320697320; // "This is "
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h612076657279206c; // "a very l"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6f6e672073656372; // "ong secr"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6574207061737370; // "et passp"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6872617365207573; // "hrase us"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h656420666f722048; // "ed for H"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4d41432061757468; // "MAC auth"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h656e746963617469; // "enticati"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6f6e207465737421; // "on test!"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h2121000000000000; // "!!......"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Write message to FIFO: "Hello, World! Th..." (65 bytes = 9 chunks)
    $display("[TB] Writing message to FIFO...");
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h48656c6c6f2c2057; // "Hello, W"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6f726c6421205468; // "orld! Th"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6973206973206120; // "is is a "
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h74657374206d6573; // "test mes"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h7361676520666f72; // "sage for"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h20484d41432d4153; // " HMAC-AS"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h434f4e2076657269; // "CON veri"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6669636174696f6e; // "fication"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h2e00000000000000; // "........"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Wait for completion and check result  
    $display("[TB] All data written, waiting for HMAC computation...");
    repeat(10) @(posedge clk);  // Give design time to start processing
    check_tag(256'h9ce0a1e0818e5bc124d982f967f43ac310dfad8c3094a62de58ceda4fcc021c1, 10000);
    wait_for_done(1000);
    
    // Wait a bit before next test
    repeat(20) @(posedge clk);

    // ========================================
    // TEST 3: Key size = 64 bytes (boundary case, no hashing)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 3: HMAC (64-byte key, 38-byte message)");
    $display("========================================");
    
    // Start operation
    $display("[TB] Starting HMAC operation (key=64 bytes, msg=38 bytes)...");
    @(posedge clk);
    config_in = {50'd38, 10'd64, 1'b1, MODE_HMAC};  // msg_size=38, key_size=64, start=1, mode=100
    @(posedge clk);

    // Clear start bit
    config_in = {50'd38, 10'd64, 1'b0, MODE_HMAC};
    
    // Write key to FIFO: "HMAC_Authenticat..." (64 bytes = 8 chunks)
    $display("[TB] Writing key to FIFO...");
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h484d41435f417574; // "HMAC_Aut"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h68656e7469636174; // "henticat"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h696f6e5f53656372; // "ion_Secr"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h65745f4b65795f46; // "et_Key_F"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6f725f5465737469; // "or_Testi"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6e675f426f756e64; // "ng_Bound"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6172795f43617365; // "ary_Case"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5f58585858585858; // "_XXXXXXX"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Write message to FIFO: "Test for exactly..." (38 bytes = 5 chunks)
    $display("[TB] Writing message to FIFO...");
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5465737420666f72; // "Test for"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h2065786163746c79; // " exactly"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h2036342d62797465; // " 64-byte"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h206b657920626f75; // " key bou"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6e646172792e0000; // "ndary..."
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;

    // Wait for completion and check result
    $display("[TB] All data written, waiting for HMAC computation...");
    repeat(10) @(posedge clk);  // Give design time to start processing
    check_tag(256'hf60d48a09ba0ee7484fb85f503ee64f7da4b0de0515b023f8d4fc0c3e3a8a1ea, 10000);
    wait_for_done(1000);
    
    // ========================================
    // TEST 4: HASH MODE
    // ========================================
    reset_design();
    
    $display("\n========================================");
    $display("TEST 4: HASH (12-byte message)");
    $display("========================================");
    $display("[TB] Starting HASH operation (msg=12 bytes)...");
    
    // Configure for HASH mode
    // MODE_HASH = 3'b001, msg_size=12, output_len=4 (32 bytes = 4*8)
    // Format: {msg_size[49:0], output_len[9:0], start[3], mode[2:0]}
    @(posedge clk);
    config_in = {50'd12, 10'd4, 1'b1, 3'b001};  // HASH mode
    @(posedge clk);
    config_in = {50'd12, 10'd4, 1'b0, 3'b001};  // Clear start
    
    $display("[TB] Design started, writing message data...");
    
    // Message: "Hello World!" = 48656c6c6f20576f726c6421 (12 bytes)
    // Write as 2 chunks: 8 bytes + 4 bytes
    $display("[TB] Writing message chunk 1 (8 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h48656c6c6f20576f;  // "Hello Wo"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing message chunk 2 (4 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h726c642100000000;  // "rld!" (padded)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    // Wait for hash computation
    $display("[TB] All data written, waiting for HASH computation...");
    repeat(10) @(posedge clk);
    
    // Expected: 690860fca70756f33bc9635bcfe022b87260275c504c4be0b0acab089a00006c
    check_tag(256'h690860fca70756f33bc9635bcfe022b87260275c504c4be0b0acab089a00006c, 10000);
    wait_for_done(1000);
    
    // ========================================
    // TEST 5: CXOF MODE
    // ========================================
    reset_design();
    
    $display("\n========================================");
    $display("TEST 5: CXOF (custom=5 bytes, message=12 bytes)");
    $display("========================================");
    $display("[TB] Starting CXOF operation...");
    
    // Configure for CXOF mode
    // MODE_CXOF = 3'b010, msg_size=12, custom_size=13 (8 bytes size word + 5 bytes data), output_len=4 (32 bytes)
    // Custom format: First 64-bit word contains size in bits (0x28 = 40 bits = 5 bytes), then actual custom data
    // Format: {msg_size[29:0], custom_size[19:0], output_len[9:0], start[3], mode[2:0]}
    @(posedge clk);
    config_in = {30'd12, 20'd13, 10'd4, 1'b1, 3'b010};  // CXOF mode (custom_size=13 bytes total: 8+5)
    @(posedge clk);
    config_in = {30'd12, 20'd13, 10'd4, 1'b0, 3'b010};  // Clear start
    
    $display("[TB] Design started, writing custom string + message...");
    
    // CXOF custom format: First word = size in bits, then data
    // Custom: "MyApp" = 5 bytes = 40 bits = 0x28
    $display("[TB] Writing custom size (40 bits in first word)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h2800000000000000;  // Size: 40 bits (5 bytes)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    // Now write the actual custom string data: "MyApp" = 4d79417070
    $display("[TB] Writing custom string data (5 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h4d79417070000000;  // "MyApp" (padded)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    // Message: "Test message" = 54657374206d657373616765 (12 bytes)
    $display("[TB] Writing message chunk 1 (8 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h54657374206d6573;  // "Test mes"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing message chunk 2 (4 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h7361676500000000;  // "sage" (padded)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    // Wait for CXOF computation
    $display("[TB] All data written, waiting for CXOF output...");
    repeat(10) @(posedge clk);
    
    // Check status
    $display("[TB] Status after data write: busy=%b, done=%b, input_empty=%b, output_empty=%b", 
             dut_busy, dut_done, input_fifo_empty, output_fifo_empty);
    
    // For CXOF, check output FIFO instead of tag
    // Expected output: 96368e4f65a26b753a9e607fa793ef0ae1bd8235bf94e5ab6b404fea0f2ffca4 (32 bytes = 4 reads)
    $display("[TB] Reading output from output FIFO...");
    wait_for_done(10000);
    
    // Read 4 x 64-bit words from output FIFO
    repeat(5) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 1: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h96368e4f65a26b75)
                $display("[TB] ✗ ERROR - Output mismatch! Expected: 96368e4f65a26b75");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 2: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h3a9e607fa793ef0a)
                $display("[TB] ✗ ERROR - Output mismatch! Expected: 3a9e607fa793ef0a");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 3: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'he1bd8235bf94e5ab)
                $display("[TB] ✗ ERROR - Output mismatch! Expected: e1bd8235bf94e5ab");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 4: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h6b404fea0f2ffca4)
                $display("[TB] ✗ ERROR - Output mismatch! Expected: 6b404fea0f2ffca4");
        end
    end
    
    $display("[TB] ✓ CXOF test completed");
    
    // ========================================
    // TEST 6: HASH - 16 bytes
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 6: HASH - 16 bytes");
    $display("========================================");
    $display("[TB] Starting HASH operation (msg=16 bytes)...");
    
    @(posedge clk);
    config_in = {50'd16, 10'd4, 1'b1, 3'b001};
    @(posedge clk);
    config_in = {50'd16, 10'd4, 1'b0, 3'b001};
    
    $display("[TB] Writing message data...");
    // Message: "ASCON_HASH_TEST!" (16 bytes)
    @(posedge clk);
    input_fifo_wr_data = 64'h4153434f4e5f4841;  // "ASCON_HA"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h53485f5445535421;  // "SH_TEST!"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    $display("[TB] All data written, waiting for HASH computation...");
    
    // Check expected hash (generated from simulation - verify with Python later)
    check_tag(256'h7085d36c88d9c808b7fd3d4b8dc771f8a5e4fe7a57258fa21dcb5f2250a1ce61, 10000);
    wait_for_done(1000);
    $display("[TB] ✓ HASH TEST 6 completed");
    
    // ========================================
    // TEST 7: HASH - 40 bytes
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 7: HASH - 40 bytes");
    $display("========================================");
    $display("[TB] Starting HASH operation (msg=40 bytes)...");
    
    @(posedge clk);
    config_in = {50'd40, 10'd4, 1'b1, 3'b001};
    @(posedge clk);
    config_in = {50'd40, 10'd4, 1'b0, 3'b001};
    
    $display("[TB] Writing message data...");
    // Message: "The quick brown fox jumps over the lazy" (40 bytes)
    @(posedge clk);
    input_fifo_wr_data = 64'h5468652071756963;  // "The quic"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h6b2062726f776e20;  // "k brown "
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h666f78206a756d70;  // "fox jump"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h73206f7665722074;  // "s over t"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h6865206c617a7920;  // "he lazy "
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    $display("[TB] All data written, waiting for HASH computation...");
    
    // Check expected hash (from simulation - verify with Python later)
    check_tag(256'ha687ce89cee613ffbb3ba285fc349e216f0e3f5cb6b5e509cb5d82b7569cc2e5, 10000);
    wait_for_done(1000);
    $display("[TB] ✓ HASH TEST 7 completed");
    
    // ========================================
    // TEST 8: HASH - 72 bytes (9 blocks)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 8: HASH - 72 bytes");
    $display("========================================");
    $display("[TB] Starting HASH operation (msg=72 bytes)...");
    
    @(posedge clk);
    config_in = {50'd72, 10'd4, 1'b1, 3'b001};
    @(posedge clk);
    config_in = {50'd72, 10'd4, 1'b0, 3'b001};
    
    $display("[TB] Writing message data...");
    // Message: "ASCON-Hash is a cryptographic hash function from the ASCON family!" (72 bytes)
    @(posedge clk);
    input_fifo_wr_data = 64'h4153434f4e2d4861;  // "ASCON-Ha"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h73682069732061;  // "sh is a"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h2063727970746f67;  // " cryptog"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h7261706869632068;  // "raphic h"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h73682066756e6374;  // "sh funct"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h696f6e2066726f6d;  // "ion from"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h2074686520415343;  // " the ASC"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h4f4e2066616d696c;  // "ON famil"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h7921000000000000;  // "y!"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    $display("[TB] All data written, waiting for HASH computation...");
    
    // Check expected hash (from simulation - verify with Python later)
    check_tag(256'h7d8ed5267821fd5cea4404f37aae676a966df5e9f9712c019862b684fe080ca0, 10000);
    wait_for_done(1000);
    $display("[TB] ✓ HASH TEST 8 completed");
    
    // ========================================
    // TEST 9: CXOF - Longer custom (10 bytes)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 9: CXOF - 10-byte custom, 20-byte message");
    $display("========================================");
    $display("[TB] Starting CXOF operation...");
    
    // custom_size = 8 (size word) + 10 (data) = 18 bytes
    // message_size = 20 bytes
    @(posedge clk);
    config_in = {30'd20, 20'd18, 10'd4, 1'b1, 3'b010};
    @(posedge clk);
    config_in = {30'd20, 20'd18, 10'd4, 1'b0, 3'b010};
    
    $display("[TB] Writing custom size (80 bits in first word)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h5000000000000000;  // Size: 80 bits (10 bytes)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing custom string data (10 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h4d79417070563100;  // "MyAppV1."
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h3030000000000000;  // "00"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing message data (20 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h5465737420646174;  // "Test dat"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h6120666f72204358;  // "a for CX"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h4f46000000000000;  // "OF"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    $display("[TB] All data written, waiting for CXOF output...");
    wait_for_done(10000);
    
    // Read 4 x 64-bit words from output FIFO (TEST 9 expected values from simulation)
    repeat(5) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 1: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h2be1808df825564c)
                $display("[TB] ✗ ERROR - Expected: 2be1808df825564c");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 2: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h8ae5bc61f02ccdbe)
                $display("[TB] ✗ ERROR - Expected: 8ae5bc61f02ccdbe");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 3: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'hf55aaac29732a80c)
                $display("[TB] ✗ ERROR - Expected: f55aaac29732a80c");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 4: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h97fa0e9734a59e83)
                $display("[TB] ✗ ERROR - Expected: 97fa0e9734a59e83");
        end
    end
    
    $display("[TB] ✓ CXOF TEST 9 completed");
    
    // ========================================
    // TEST 10: CXOF - Short custom (3 bytes), long message (48 bytes)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 10: CXOF - 3-byte custom, 48-byte message");
    $display("========================================");
    $display("[TB] Starting CXOF operation...");
    
    // custom_size = 8 + 3 = 11 bytes
    // message_size = 48 bytes
    @(posedge clk);
    config_in = {30'd48, 20'd11, 10'd4, 1'b1, 3'b010};
    @(posedge clk);
    config_in = {30'd48, 20'd11, 10'd4, 1'b0, 3'b010};
    
    $display("[TB] Writing custom size (24 bits in first word)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h1800000000000000;  // Size: 24 bits (3 bytes)
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing custom string data (3 bytes)...");
    @(posedge clk);
    input_fifo_wr_data = 64'h4142430000000000;  // "ABC"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] Writing message data (48 bytes)...");
    // Repeating pattern
    @(posedge clk);
    input_fifo_wr_data = 64'h3031323334353637;  // "01234567"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h3839616263646566;  // "89abcdef"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h6768696a6b6c6d6e;  // "ghijklmn"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h6f70717273747576;  // "opqrstuv"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h7778797a41424344;  // "wxyzABCD"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    repeat(10) @(posedge clk);
    
    @(posedge clk);
    input_fifo_wr_data = 64'h4546474849494b4c;  // "EFGHIIKL"
    input_fifo_wr_en = 1;
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    $display("[TB] All data written, waiting for CXOF output...");
    wait_for_done(10000);
    
    // Read 4 x 64-bit words from output FIFO (TEST 10 expected values from simulation)
    repeat(5) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 1: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h1319ba32768bb4af)
                $display("[TB] ✗ ERROR - Expected: 1319ba32768bb4af");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 2: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'ha698af76ec633ec3)
                $display("[TB] ✗ ERROR - Expected: a698af76ec633ec3");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 3: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h963769ce8aae8ba4)
                $display("[TB] ✗ ERROR - Expected: 963769ce8aae8ba4");
        end
    end
    
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Output word 4: %016h", output_fifo_rd_data);
            if (output_fifo_rd_data !== 64'h0de343a27b6fc3a9)
                $display("[TB] ✗ ERROR - Expected: 0de343a27b6fc3a9");
        end
    end
    
    $display("[TB] ✓ CXOF TEST 10 completed");
    
//     ========================================
//     TEST 11: AEAD - Encryption (no AD, short plaintext)
//     ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 11: AEAD - Encryption (16-byte plaintext, no AD)");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");
    
    
    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h2f2e2d2c2b2a29282726252423222120;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;
    
    @(posedge clk);
    nonce_in = 128'h4f4e4d4c4b4a49484746454443424140;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;
    
    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd23, 20'd20, 9'd2, 1'b1, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd23, 20'd20, 9'd2, 1'b1, 1'b0, MODE_AEAD};  // Clear start
    
    
    // Associated data: "MULTIBLOCKADHERETEST" (20 bytes - spans 4 blocks)
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4D55_4C54_4942_4C4F;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h434B_4144_4845_5245;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
 
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5445_5354_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
        
        
     // Plaintext: "MULTIBLOCKPLAINTEXTHERE" (23 bytes - spans 4 blocks) - CORRECTED!
    $display("[TB] Writing plaintext data (16 bytes)...");
    // Plaintext: "ASCON AEAD Test!"
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4D55_4C54_4942_4C4F;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h434B_504C_4149_4E54;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4558_5448_4552_4500;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);



    
    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);
    
    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");
    
    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);
    
    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end
    
    // Read word 2  
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end
    
        // Now wait for done signal and tag
    wait_for_done(5000);
    
    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);
    
    
    // ========================================
    // TEST 11: AEAD - Encryption (no AD, short plaintext)
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 11: AEAD - Encryption (16-byte plaintext, no AD)");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");
    
    
    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h2f2e2d2c2b2a29282726252423222120;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;
    
    @(posedge clk);
    nonce_in = 128'h4f4e4d4c4b4a49484746454443424140;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;
    
    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd23, 20'd20, 9'd2, 1'b0, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd23, 20'd20, 9'd2, 1'b0, 1'b0, MODE_AEAD};  // Clear start
    
    
    // Associated data: "MULTIBLOCKADHERETEST" (20 bytes - spans 4 blocks)
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4D55_4C54_4942_4C4F;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h434B_4144_4845_5245;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
 
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5445_5354_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
        
     // Plaintext: "MULTIBLOCKPLAINTEXTHERE" (23 bytes - spans 4 blocks) - CORRECTED!
    $display("[TB] Writing plaintext data (16 bytes)...");
    // Plaintext: "ASCON AEAD Test!"
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'hDE88_ACBA_ECB7_06DE;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h2A0B_A64A_1DD4_9BFC;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'hB3B1_2C1C_0C0C_5100;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    
    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);
    
    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");
    
    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);
    
    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end
    
    // Read word 2  
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end
    
    // Now wait for done signal and tag
    wait_for_done(5000);
    
    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);
    
    $display("[TB] ✓ AEAD TEST 11 completed");
    
    
    // ========================================
    // TEST 12: AEAD - Encryption 
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 12: AEAD - Encryption (16-byte plaintext, no AD)");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");
    
    
    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h3f3e3d3c3b3a39383736353433323130;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;
    
    @(posedge clk);
    nonce_in = 128'h5f5e5d5c5b5a59585756555453525150;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;
    
    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd39, 20'd35, 9'd3, 1'b1, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd39, 20'd35, 9'd3, 1'b1, 1'b0, MODE_AEAD};  // Clear start
    
    
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4C41_5247_454D_554C;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5449_424C_4F43_4B41;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
 
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5554_4845_4E54_4943;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4154_4544_4441_5441;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h3132_3300_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
        
        
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4C41_5247_454D_554C;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5449_424C_4F43_4B50;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4C41_494E_5445_5854;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h464F_524D_4F52_4541;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
            repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4456_414E_4345_4400;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);



    
    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);
    
    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");
    
    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);
    
    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end
    
    // Read word 2  
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end
    
        // Now wait for done signal and tag
    wait_for_done(5000);
    
    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);
    
    
    // ========================================
    // TEST 12: AEAD - Decryption
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 11: AEAD - Encryption (16-byte plaintext, no AD)");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");
    
    
    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h3f3e3d3c3b3a39383736353433323130;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;
    
    @(posedge clk);
    nonce_in = 128'h5f5e5d5c5b5a59585756555453525150;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;
    
    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd39, 20'd35, 9'd3, 1'b0, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd39, 20'd35, 9'd3, 1'b0, 1'b0, MODE_AEAD};  // Clear start
    
    
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4C41_5247_454D_554C;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5449_424C_4F43_4B41;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
 
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h5554_4845_4E54_4943;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4154_4544_4441_5441;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h3132_3300_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    
    $display("[TB] Writing plaintext data (16 bytes)...");
    // Plaintext: "ASCON AEAD Test!"
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h62B0_B745_88F4_AD93;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h35EF_173C_9F0B_0DD2;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h725A_CF06_B6A2_224F;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'hCD5A_5940_A41B_D072;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
            repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'hFF40_72BC_59FE_4D00;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h0000_0000_0000_0000;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;
    
    repeat(10) @(posedge clk);
    
    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);
    
    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");
    
    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);
    
    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end
    
    // Read word 2  
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end
    
    // Now wait for done signal and tag
    wait_for_done(5000);
    
    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);
    
    $display("[TB] ✓ AEAD TEST 12 completed");
    
    
    
     
    // ========================================
    // TEST 13: AEAD - Encryption
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 13: AEAD - Encryption");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");


    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h1f1e1d1c1b1a19181716151413121110;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;

    @(posedge clk);
    nonce_in = 128'h3f3e3d3c3b3a39383736353433323130;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;

    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd16, 20'd16, 9'd1, 1'b1, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd16, 20'd16, 9'd1, 1'b1, 1'b0, MODE_AEAD};  // Clear start



    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4655_4C4C_424C_4F43;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4B41_4454_4553_5421;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;


    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4655_4C4C_424C_4F43;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4B50_5454_4553_5421;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);



    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);

    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");

    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);

    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end

    // Read word 2
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end

        // Now wait for done signal and tag
    wait_for_done(5000);

    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);


    // ========================================
    // TEST 13: AEAD - Decryption
    // ========================================
    reset_design();
    $display("\n========================================");
    $display("TEST 13: AEAD - Decryption ");
    $display("========================================");
    $display("[TB] Starting AEAD encryption...");


    // Set key and nonce first
    @(posedge clk);
    key_in = 128'h1f1e1d1c1b1a19181716151413121110;  // 128-bit key
    key_wr_en = 1;
    $display("[TB DEBUG] Key written: %h", key_in);
    @(posedge clk);
    key_wr_en = 0;

    @(posedge clk);
    nonce_in = 128'h3f3e3d3c3b3a39383736353433323130;  // 128-bit nonce
    nonce_wr_en = 1;
    @(posedge clk);
    nonce_wr_en = 0;

    // Configure for AEAD mode
    // Format: {pt_size[29:0], ad_size[19:0], output_len[8:0], encrypt[4], start[3], mode[2:0]}
    // pt_size=16, ad_size=0, output_len=2 (16 bytes = 2x8), encrypt=1, start=1
    @(posedge clk);
    config_in = {30'd16, 20'd16, 9'd1, 1'b0, 1'b1, MODE_AEAD};
    @(posedge clk);
    config_in = {30'd16, 20'd16, 9'd1, 1'b0, 1'b0, MODE_AEAD};  // Clear start

        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4655_4C4C_424C_4F43;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 1: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h4B41_4454_4553_5421;
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

    $display("[TB] Writing plaintext data (16 bytes)...");
    // Plaintext: "ASCON AEAD Test!"
    repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h3F04_27E0_E1EA_FA99;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

        repeat(10) @(posedge clk);
    input_fifo_wr_data = 64'h6BD6_BDDE_D502_646D;  // "ASCON AE"
    input_fifo_wr_en = 1;
    $display("[TB DEBUG] Written chunk 2: %h, busy=%b", input_fifo_wr_data, dut_busy);
    @(posedge clk);
    input_fifo_wr_en = 0;

    repeat(10) @(posedge clk);

    $display("[TB] All data written, waiting for AEAD ciphertext output...");
    $display("[TB DEBUG] After writes: busy=%b, done=%b", dut_busy, dut_done);

    // Read ciphertext from output FIFO (16 bytes = 2 x 64-bit words due to AEAD double write)
    // For AEAD: 128-bit blocks → 2×64-bit FIFO writes per block
    $display("[TB] Reading ciphertext...");

    // Wait for first word to appear in output FIFO
    repeat(200) @(posedge clk);

    // Read word 1
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 1: %016h", output_fifo_rd_data);
        end
    end else begin
        $display("[TB] ERROR: Output FIFO empty!");
    end

    // Read word 2
    repeat(2) @(posedge clk);
    if (!output_fifo_empty) begin
        output_fifo_rd_en = 1;
        @(posedge clk);
        output_fifo_rd_en = 0;
        @(posedge clk);
        if (output_fifo_rd_valid) begin
            $display("[TB] Ciphertext word 2: %016h", output_fifo_rd_data);
        end
    end

    // Now wait for done signal and tag
    wait_for_done(5000);

    // Check tag
    repeat(5) @(posedge clk);
    $display("[TB] AEAD Tag: %032h", tag_out[127:0]);

    $display("[TB] ✓ AEAD TEST 13 completed");


    // ========================================
    // Final Section
    // ========================================
    $finish;
  end
  
  // Timeout watchdog
  initial begin
    #(CLOCK_PERIOD * TIMEOUT_CYCLES * 2);
    $display("[TB] WATCHDOG TIMEOUT!");
    $finish;
  end

endmodule

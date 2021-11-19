function unit_test_client(verbose=true)
    bits_tab = Vector{UInt8}(make_bitvector(UT_BITS_TAB, UT_BITS_NB))
    input_bits_tab = Vector{UInt8}(make_bitvector(UT_INPUT_BITS_TAB, UT_INPUT_BITS_NB))

    errno = Libc.errno
    ctx_cl = TcpContext("127.0.0.1", 1502)
    modbus_set_debug(ctx_cl, verbose)
    modbus_flush(ctx_cl)
    #modbus_set_error_recovery(ctx_cl, Int(MODBUS_ERROR_RECOVERY_LINK) |
    #    Int(MODBUS_ERROR_RECOVERY_PROTOCOL))
    rc,old_response_to_sec,old_response_to_usec = modbus_get_response_timeout(ctx_cl)
    modbus_connect(ctx_cl) >= 0 || error("connection failed")
    @testset "1/1 No response timeout modification on connect" begin
        rc,new_response_to_sec,new_response_to_usec = modbus_get_response_timeout(ctx_cl)
        @test ((old_response_to_sec,old_response_to_usec)
               == (new_response_to_sec,new_response_to_usec))
    end
#    @testset "Tests involving connection to server" begin
        @testset "Single coil bits" begin
            verbose && println("1/2 modbus_write_bit: ")
            rc = modbus_write_bit(ctx_cl, UT_BITS_ADDRESS, 0x1)
            @test rc == 1;modbus_flush(ctx_cl)
            verbose && println("2/2 modbus_read_bits: ")
            rc,rp_bits = modbus_read_bits(ctx_cl, UT_BITS_ADDRESS, 0x1)
            @test rc == 1
            @test rp_bits[1] == 1
        end
        
        @testset "Multiple coil bits" begin
            verbose && println("1/2 modbus_write_bits: ")
            rc = modbus_write_bits(ctx_cl, UT_BITS_ADDRESS, bits_tab)
            @test rc == UT_BITS_NB
            verbose && println("2/2 modbus_read_bits: ")
            rc,rp_bits = modbus_read_bits(ctx_cl, UT_BITS_ADDRESS, UT_BITS_NB)
            @test rc == UT_BITS_NB
            @test rp_bits == bits_tab
        end

        @testset "Discrete inputs" begin
            verbose && println("1/1 modbus_read_input_bits: ")
            rc,rp_bits = modbus_read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                                UT_INPUT_BITS_NB)
            @test rc == UT_INPUT_BITS_NB
            @test rp_bits == input_bits_tab
        end

        @testset "Holding registers" begin
            #  Single register
            verbose && println("1/2 modbus_write_register: ")
            rc = modbus_write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x1234)
            @test rc == 1
            verbose && println("2/2 modbus_read_registers: ")
            rc,rp_regs = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 1)
            @test rc == 1
            @test rp_regs[] == 0x1234
            # Many registers
            verbose && println("1/5 modbus_write_registers: ")
            rc = modbus_write_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_TAB)
            @test rc == UT_REGISTERS_NB
            verbose && println("2/5 modbus_read_registers: ")
            rc,rp_regs = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                               UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB
            @test rp_regs == UT_REGISTERS_TAB
            verbose && println("3/5 modbus_read_registers (0): ")
            rc,_ = @test_logs((:warn, r"Illegal data value"),
                              modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 0))
            errn = errno()
            @test rc == -1 && errn == EMBXILVAL
            rp_regs = zeros(UInt16, UT_REGISTERS_NB - 1)
            verbose && println("4/5 modbus_write_and_read_registers: ")
            rc,rp_regs = modbus_write_and_read_registers(ctx_cl,
                                                         UT_REGISTERS_ADDRESS + 1,
                                                         rp_regs,
                                                         UT_REGISTERS_ADDRESS,
                                                         UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB
            @test rp_regs[1] == UT_REGISTERS_TAB[1]
        end

        @testset "Input registers" begin
            verbose && println("1/1 modbus_read_input_registers: ")
            rc,rp_reg = modbus_read_input_registers(ctx_cl,
                                                    UT_INPUT_REGISTERS_ADDRESS,
                                                    UT_INPUT_REGISTERS_NB)
            @test rc == UT_INPUT_REGISTERS_NB

            verbose && println("1/1 Write mask: ")
            rc = modbus_write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x12)
            rc = modbus_mask_write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x00F2, 0x0025)
            @test rc != -1
            rc,rp_regs = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 1)
            @test rp_regs[1] == 0x17
        end

        @testset "Illegal data address" begin
            ## The mapping begins at the defined addresses and ends at address +
            ## nb_points so these addresses are not valid.
            verbose && println("* modbus_read_bits (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_bits(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_bits (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_bits(ctx_cl, UT_BITS_ADDRESS, UT_BITS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_input_bits (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_input_bits(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_input_bits (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                                      UT_INPUT_BITS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_registers(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_registers (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                                     UT_REGISTERS_NB_MAX + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_input_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_read_input_registers(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_read_input_registers (max): ")
            rc,_ =
                @test_logs((:warn, r"Illegal data address"),
                           modbus_read_input_registers(ctx_cl, UT_INPUT_REGISTERS_ADDRESS,
                                                       UT_INPUT_REGISTERS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_bit (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_bit(ctx_cl, 0, 0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_bit (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_bit(ctx_cl, UT_BITS_ADDRESS + UT_BITS_NB, 0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_coils (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_bits(ctx_cl, 0, [0x01]))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_coils (max): ")
            rp_bits = zeros(UInt8, UT_BITS_NB)
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_bits(ctx_cl, UT_BITS_ADDRESS + UT_BITS_NB, rp_bits))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_register (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_register(ctx_cl, 0x0, 0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_register (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_register(ctx_cl,
                                                  UT_REGISTERS_ADDRESS + UT_REGISTERS_NB_MAX,
                                                  0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_registers (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_registers(ctx_cl, 0, UInt16[1]))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_registers (max): ")
            rp_regs = zeros(UInt16, UT_REGISTERS_NB)
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_write_registers(ctx_cl,
                                                   UT_REGISTERS_ADDRESS +
                                                       UT_REGISTERS_NB_MAX,
                                                   rp_regs))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_mask_write_registers (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_mask_write_register(ctx_cl, 0, 0x00F2, 0x0025))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_mask_write_registers (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            modbus_mask_write_register(ctx_cl,
                                                       UT_REGISTERS_ADDRESS +
                                                           UT_REGISTERS_NB_MAX,
                                                       0x00F2, 0x0025))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_and_read_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_write_and_read_registers(ctx_cl, 0, rp_regs[1:1],
                                                               0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* modbus_write_and_read_registers (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               modbus_write_and_read_registers(ctx_cl,
                                                               UT_REGISTERS_ADDRESS +
                                                                   UT_REGISTERS_NB_MAX,
                                                               rp_regs,
                                                               UT_REGISTERS_ADDRESS +
                                                                   UT_REGISTERS_NB_MAX,
                                                               UT_REGISTERS_NB))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD
        end

        @testset "Too many data" begin
            verbose && println("* modbus_read_bits: ")
            rc, _ = @test_logs((:warn, r"Too many data"),
                               modbus_read_bits(ctx_cl, UT_BITS_ADDRESS,
                                                MODBUS_MAX_READ_BITS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* modbus_read_input_bits: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              modbus_read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                                     MODBUS_MAX_READ_BITS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* modbus_read_registers: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                                    MODBUS_MAX_READ_REGISTERS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* modbus_read_input_registers: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              modbus_read_input_registers(ctx_cl, UT_INPUT_REGISTERS_ADDRESS,
                                                          MODBUS_MAX_READ_REGISTERS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* modbus_write_bits: ")
            rp_bits = zeros(UInt8,  MODBUS_MAX_WRITE_BITS + 1)
            rc = @test_logs((:warn, r"Too many data"),
                            modbus_write_bits(ctx_cl, UT_BITS_ADDRESS, rp_bits))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* modbus_write_registers: ")
            rp_regs = zeros(UInt16, MODBUS_MAX_WRITE_REGISTERS + 1)
            rc = @test_logs((:warn, r"Too many data"),
                            modbus_write_registers(ctx_cl, UT_REGISTERS_ADDRESS, rp_regs))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA
        end

        @testset "Slave reply" begin

            old_slave = modbus_get_slave(ctx_cl)
            verbose && println("1/3 Response from slave $(INVALID_SERVER_ID): ")
            modbus_set_slave(ctx_cl, INVALID_SERVER_ID)
            rc,_ = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB

            rc = modbus_set_slave(ctx_cl, MODBUS_BROADCAST_ADDRESS)
            @test rc != -1

            verbose && println("2/3 Reply after a query with unit id == 0: ")
            rc,_ = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB

            # Restore slave
            modbus_set_slave(ctx_cl, old_slave)
            verbose && println("3/3 Response with an invalid TID or slave: ")
            rc,_= @test_logs((:warn, r"Invalid data"),
                             modbus_read_registers(ctx_cl,
                                                   UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE,
                                                   1))
            errn = errno()
            @test rc == -1  && errn == EMBBADDATA
            modbus_flush(ctx_cl)
            verbose && println("2/2 Report slave ID:")
            #
            rc,rp_bits = modbus_report_slave_id(ctx_cl, NB_REPORT_SLAVE_ID)
            # Run status indicator is ON
            @test rc > 1 && rp_bits[2] == 0xFF

            # Save original timeout
            rc,old_response_to_sec,old_response_to_usec =
                modbus_get_response_timeout(ctx_cl)
            rc,old_byte_to_sec,old_byte_to_usec = modbus_get_byte_timeout(ctx_cl)
            einval_reg = Regex("$(Libc.strerror(Libc.EINVAL))")
            verbose && println("1/6 Invalid response timeout (zero): ")
            rc =  @test_logs((:warn, einval_reg),
                             modbus_set_response_timeout(ctx_cl, 0, 0))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            verbose && println("2/6 Invalid response timeout (too large us): ")
            rc = @test_logs((:warn, einval_reg),
                            modbus_set_response_timeout(ctx_cl, 0, 1000000))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            verbose && println("3/6 Invalid byte timeout (too large us): ")
            rc = @test_logs((:warn, einval_reg),
                            modbus_set_byte_timeout(ctx_cl, 0, 1000000))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            # # verbose && println("4/6 1us response timeout: ")
            # etimedout_reg = Regex("$(Libc.strerror(Libc.ETIMEDOUT))")
            # modbus_set_response_timeout(ctx_cl, 0, 1)
            # rc,_ = @test_logs((:warn, etimedout_reg),
            #                   modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
            #                                         UT_REGISTERS_NB))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT
            
            # # # A wait and flush operation is done by the error recovery code of
            # # # libmodbus but after a sleep of current response timeout
            # # # so 0 can be too short!
            # sleep(old_response_to_sec + 1e-6*old_response_to_usec)
            # modbus_flush(ctx_cl)

            # # # Trigger a special behaviour on server to wait for 0.5 second before
            # # # replying whereas allowed timeout is 0.2 second
            # verbose && println("5/6 Too short response timeout (0.2s < 0.5s): ")
            # modbus_set_response_timeout(ctx_cl, 0, 200000)
            # rc,_ =  @test_logs((:warn, etimedout_reg),
            #                    modbus_read_registers(ctx_cl,
            #                                          UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT

            # # Wait for reply (0.2 + 0.4 > 0.5 s) and flush before continue
            # sleep(0.4)
            # modbus_flush(ctx_cl)

            # verbose && println("6/6 Adequate response timeout (0.6s > 0.5s): ")
            # modbus_set_response_timeout(ctx_cl, 0, 600000)
            # rc,_ = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1)
            # @test rc == 1
            # modbus_flush(ctx_cl)
            # # Disable the byte timeout.
            #   The full response must be available in the 600ms interval
            # verbose && println("7/7 Disable byte timeout: ")
            # rc=modbus_set_byte_timeout(ctx_cl, 0, 0);println("byte timeout disable $(rc)")
            # rc,_ = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1)
            # @test rc == 1
            # # # Restore original response and byte timeout
            # modbus_set_response_timeout(ctx_cl, old_response_to_sec, old_response_to_usec)
            # modbus_set_byte_timeout(ctx_cl, old_byte_to_sec, old_byte_to_usec)
            # sleep(0.4)
            # modbus_flush(ctx_cl)
            # # The test server is only able to test byte timeouts with the TCP
            # # backend
            # # Timeout of 3ms between bytes
            # verbose && println("1/2 Too small byte timeout (3ms < 5ms): ")
            # modbus_set_byte_timeout(ctx_cl, 0, 3000)
            # rc,_ = @test_logs((:warn, etimedout_reg),
            #                   modbus_read_registers(ctx_cl,
            #                                         UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS,
            #                                         1))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT

            # # Wait remaing bytes before flushing
            # sleep(11 * 0.005)
            # modbus_flush(ctx_cl)

            # # # Timeout of 7ms between bytes
            # modbus_set_byte_timeout(ctx_cl, 0, 7000)
            # verbose && println("2/2 Adapted byte timeout (7ms > 5ms): ")
            # rc,_ = modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS, 1)
            # @test rc == 1

            # # Restore original timeouts
            modbus_set_response_timeout(ctx_cl, old_response_to_sec, old_response_to_usec)
            modbus_set_byte_timeout(ctx_cl, old_byte_to_sec, old_byte_to_usec)
            sleep(0.4)
            modbus_flush(ctx_cl)
        end
        @testset "Bad response" begin
            verbose && println("* modbus_read_registers with invalid data: ")
            rc,_= @test_logs((:warn, r"Invalid data"),
                             modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                                   UT_REGISTERS_NB_SPECIAL))
            errn = errno()
            @test rc == -1 && errn == EMBBADDATA
            verbose && println("* modbus_read_registers at special address: ")
            rc,_ =  @test_logs((:warn, r"Slave device or server is busy"),
                               modbus_read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SPECIAL,
                                                     UT_REGISTERS_NB))
            errn = errno()
            @test rc == -1 && errn == EMBXSBUSY
        end
        modbus_close(ctx_cl)
        modbus_free!(ctx_cl)
        @testset "Invalid initialization" begin
            einval_reg = Regex("$(Libc.strerror(Libc.EINVAL))")
            ctx_cl = @test_logs((:warn, einval_reg), RtuContext("", 1, :none, 0, 0))
            errn = errno()
            @test !modbus_context_valid(ctx_cl) && errn == Libc.EINVAL
    
            ctx = @test_logs((:warn, einval_reg), RtuContext("/dev/dummy", 0, :none, 0, 0))
            errn = errno()
            @test !modbus_context_valid(ctx_cl) && errn == Libc.EINVAL
        end
#    end
    nothing
end

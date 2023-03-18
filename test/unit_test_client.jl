function unit_test_client(verbose=true)
    bits_tab = Vector{UInt8}(make_bitvector(UT_BITS_TAB, UT_BITS_NB))
    input_bits_tab = Vector{UInt8}(
        make_bitvector(UT_INPUT_BITS_TAB, UT_INPUT_BITS_NB))

    errno = Libc.errno
    ctx_cl = TcpContext("127.0.0.1", 1502)
    modbus_set_debug!(ctx_cl, verbose)
    modbus_flush!(ctx_cl)
    #modbus_set_error_recovery(ctx_cl, Int(MODBUS_ERROR_RECOVERY_LINK) |
    #    Int(MODBUS_ERROR_RECOVERY_PROTOCOL))
    @testset "LibModbus.jl tests" begin
        @testset "Initialization, setting properties and freeing " begin
            ctx = RtuContext("/dev/dummy", 9600, :none, 8, 1);
            verbose && println("check validity of constructed context: ")
            @test ctx.valid

            verbose && println("1/2 serial line properties:")
            ctx.rts = :RTS_UP
            @test ctx.rts === :RTS_UP
            ctx.rts = :RTS_DOWN
            @test ctx.rts === :RTS_DOWN
            ctx.rts = :RTS_NONE
            @test ctx.rts === :RTS_NONE

            verbose && println("2/2 serial line properties:")
            ctx.rts_delay = 1000
            @test ctx.rts_delay == 1000
            ctx.rts_delay = 2000
            @test ctx.rts_delay == 2000

            verbose && println("2/2 common properties:")
            ctx.slave_address = 0
            @test ctx.slave_address == 0
            ctx.slave_address = 3
            @test ctx.slave_address == 3
            
            modbus_free!(ctx)
            @test !ctx.valid
        end
        old_response_to_sec,old_response_to_usec = ctx_cl.response_timeout
        connect(ctx_cl) >= 0 || error("connection failed")
        @testset "No response timeout modification on connect" begin
            new_response_to_sec,new_response_to_usec = ctx_cl.response_timeout
            @test ((old_response_to_sec,old_response_to_usec)
                   == (new_response_to_sec,new_response_to_usec))
        end
        @testset "Single coil bits" begin
            verbose && println("1/2 write_bit: ")
            rc = write_bit(ctx_cl, UT_BITS_ADDRESS, 0x1)
            @test rc == 1;modbus_flush!(ctx_cl)
            verbose && println("2/2 read_bits: ")
            rc,rp_bits = read_bits(ctx_cl, UT_BITS_ADDRESS, 0x1)
            @test rc == 1
            @test length(rp_bits) > 0 && rp_bits[1] == 1
        end
        
        @testset "Multiple coil bits" begin
            verbose && println("1/2 write_bits: ")
            rc = write_bits(ctx_cl, UT_BITS_ADDRESS, bits_tab)
            @test rc == UT_BITS_NB
            verbose && println("2/2 read_bits: ")
            rc,rp_bits = read_bits(ctx_cl, UT_BITS_ADDRESS, UT_BITS_NB)
            @test rc == UT_BITS_NB
            @test rp_bits == bits_tab
        end

        @testset "Discrete inputs" begin
            verbose && println("1/1 read_input_bits: ")
            rc,rp_bits = read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                         UT_INPUT_BITS_NB)
            @test rc == UT_INPUT_BITS_NB
            @test rp_bits == input_bits_tab
        end

        @testset "Holding registers" begin
            #  Single register
            verbose && println("1/2 write_register: ")
            rc = write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x1234)
            @test rc == 1
            verbose && println("2/2 read_registers: ")
            rc,rp_regs = read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 1)
            @test rc == 1
            @test rp_regs[] == 0x1234
            # Many registers
            verbose && println("1/5 write_registers: ")
            rc = write_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_TAB)
            @test rc == UT_REGISTERS_NB
            verbose && println("2/5 read_registers: ")
            rc,rp_regs = read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                        UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB
            @test rp_regs == UT_REGISTERS_TAB
            verbose && println("3/5 read_registers (0): ")
            rc,_ = @test_logs((:warn, r"Illegal data value"),
                              read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 0))
            errn = errno()
            @test rc == -1 && errn == EMBXILVAL
            rp_regs = zeros(UInt16, UT_REGISTERS_NB - 1)
            verbose && println("4/5 write_and_read_registers: ")
            rc,rp_regs = write_and_read_registers(ctx_cl,
                                                  UT_REGISTERS_ADDRESS + 1,
                                                  rp_regs,
                                                  UT_REGISTERS_ADDRESS,
                                                  UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB
            @test rp_regs[1] == UT_REGISTERS_TAB[1]
        end

        @testset "Input registers" begin
            verbose && println("1/1 read_input_registers: ")
            rc,rp_reg = read_input_registers(ctx_cl,
                                             UT_INPUT_REGISTERS_ADDRESS,
                                             UT_INPUT_REGISTERS_NB)
            @test rc == UT_INPUT_REGISTERS_NB

            verbose && println("1/1 Write mask: ")
            rc = write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x12)
            rc = mask_write_register(ctx_cl, UT_REGISTERS_ADDRESS, 0x00F2,
                                     0x0025)
            @test rc != -1
            rc,rp_regs = read_registers(ctx_cl, UT_REGISTERS_ADDRESS, 1)
            @test rp_regs[1] == 0x17
        end

        @testset "Illegal data address" begin
            ## The mapping begins at the defined addresses and ends at address +
            ## nb_points so these addresses are not valid.
            verbose && println("* read_bits (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_bits(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_bits (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_bits(ctx_cl, UT_BITS_ADDRESS,
                                         UT_BITS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_input_bits (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_input_bits(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_input_bits (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                               UT_INPUT_BITS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_registers(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_registers (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                              UT_REGISTERS_NB_MAX + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_input_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               read_input_registers(ctx_cl, 0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* read_input_registers (max): ")
            rc,_ =
                @test_logs((:warn, r"Illegal data address"),
                           read_input_registers(ctx_cl,
                                                UT_INPUT_REGISTERS_ADDRESS,
                                                UT_INPUT_REGISTERS_NB + 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_bit (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_bit(ctx_cl, 0, 0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_bit (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_bit(ctx_cl, UT_BITS_ADDRESS + UT_BITS_NB,
                                      0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_coils (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_bits(ctx_cl, 0, [0x01]))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_coils (max): ")
            rp_bits = zeros(UInt8, UT_BITS_NB)
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_bits(ctx_cl, UT_BITS_ADDRESS + UT_BITS_NB,
                                       rp_bits))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_register (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_register(ctx_cl, 0x0, 0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_register (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_register(ctx_cl,
                                           UT_REGISTERS_ADDRESS + UT_REGISTERS_NB_MAX,
                                           0x01))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_registers (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_registers(ctx_cl, 0, UInt16[1]))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_registers (max): ")
            rp_regs = zeros(UInt16, UT_REGISTERS_NB)
            rc = @test_logs((:warn, r"Illegal data address"),
                            write_registers(ctx_cl,
                                            UT_REGISTERS_ADDRESS +
                                                UT_REGISTERS_NB_MAX,
                                            rp_regs))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* mask_write_registers (0): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            mask_write_register(ctx_cl, 0, 0x00F2, 0x0025))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* mask_write_registers (max): ")
            rc = @test_logs((:warn, r"Illegal data address"),
                            mask_write_register(ctx_cl,
                                                UT_REGISTERS_ADDRESS +
                                                    UT_REGISTERS_NB_MAX,
                                                0x00F2, 0x0025))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_and_read_registers (0): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               write_and_read_registers(ctx_cl, 0, rp_regs[1:1],
                                                        0, 1))
            errn = errno()
            @test rc == -1 && errn == EMBXILADD

            verbose && println("* write_and_read_registers (max): ")
            rc,_ =  @test_logs((:warn, r"Illegal data address"),
                               write_and_read_registers(ctx_cl,
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
            verbose && println("* read_bits: ")
            rc, _ = @test_logs((:warn, r"Too many data"),
                               read_bits(ctx_cl, UT_BITS_ADDRESS,
                                         MODBUS_MAX_READ_BITS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* read_input_bits: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              read_input_bits(ctx_cl, UT_INPUT_BITS_ADDRESS,
                                              MODBUS_MAX_READ_BITS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* read_registers: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                             MODBUS_MAX_READ_REGISTERS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* read_input_registers: ")
            rc,_ = @test_logs((:warn, r"Too many data"),
                              read_input_registers(ctx_cl,
                                                   UT_INPUT_REGISTERS_ADDRESS,
                                                   MODBUS_MAX_READ_REGISTERS + 1))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* write_bits: ")
            rp_bits = zeros(UInt8,  MODBUS_MAX_WRITE_BITS + 1)
            rc = @test_logs((:warn, r"Too many data"),
                            write_bits(ctx_cl, UT_BITS_ADDRESS, rp_bits))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA

            verbose && println("* write_registers: ")
            rp_regs = zeros(UInt16, MODBUS_MAX_WRITE_REGISTERS + 1)
            rc = @test_logs((:warn, r"Too many data"),
                            write_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                            rp_regs))
            errn = errno()
            @test rc == -1 && errn == EMBMDATA
        end

        @testset "Slave reply" begin
            old_slave = ctx_cl.slave_address
            verbose && println("1/3 Response from slave $(INVALID_SERVER_ID): ")
            ctx_cl.slave_address = INVALID_SERVER_ID
            rc,_ = read_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB

            rc = LM.set_slave!(ctx_cl, MODBUS_BROADCAST_ADDRESS)
            @test rc != -1

            verbose && println("2/3 Reply after a query with unit id == 0: ")
            rc,_ = read_registers(ctx_cl, UT_REGISTERS_ADDRESS, UT_REGISTERS_NB)
            @test rc == UT_REGISTERS_NB

            # Restore slave
            ctx_cl.slave_address = old_slave
            verbose && println("3/3 Response with an invalid TID or slave: ")
            rc,_= @test_logs((:warn, r"Invalid data"),
                             read_registers(ctx_cl,
                                            UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE,
                                            1))
            errn = errno()
            @test rc == -1  && errn == EMBBADDATA
            modbus_flush!(ctx_cl)
            #
            verbose && println("1/1 Report slave ID:")
            #
            rc,rp_bits = report_slave_id(ctx_cl, NB_REPORT_SLAVE_ID)
            # Run status indicator is ON
            @test_broken rc > 1 && rp_bits[2] == 0xFF
            length(rp_bits) > 2 && println(String(rp_bits[3:end]))

            # Save original timeout
            old_response_to_sec,old_response_to_usec = ctx_cl.response_timeout
            old_byte_to_sec,old_byte_to_usec = ctx_cl.byte_timeout

            einval_reg = Regex("$(Libc.strerror(Libc.EINVAL))")
            verbose && println("1/6 Invalid response timeout (zero): ")
            rc =  @test_logs((:warn, einval_reg),
                             LM.set_response_timeout(ctx_cl, 0, 0))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            verbose && println("2/6 Invalid response timeout (too large us): ")
            rc = @test_logs((:warn, einval_reg),
                            LM.set_response_timeout(ctx_cl, 0, 1000000))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            verbose && println("3/6 Invalid byte timeout (too large us): ")
            rc = @test_logs((:warn, einval_reg),
                            LM.set_byte_timeout(ctx_cl, 0, 1000000))
            errn = errno()
            @test rc == -1 && errn == Libc.EINVAL

            # # verbose && println("4/6 1us response timeout: ")
            # etimedout_reg = Regex("$(Libc.strerror(Libc.ETIMEDOUT))")
            # ctx_cl.response_timeout = (0, 1)
            # rc,_ = @test_logs((:warn, etimedout_reg),
            #                   read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
            #                                         UT_REGISTERS_NB))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT
            
            # # # A wait and flush operation is done by the error recovery code of
            # # # libmodbus but after a sleep of current response timeout
            # # # so 0 can be too short!
            # sleep(old_response_to_sec + 1e-6*old_response_to_usec)
            # modbus_flush!(ctx_cl)

            # # # Trigger a special behaviour on server to wait for 0.5 second before
            # # # replying whereas allowed timeout is 0.2 second
            # verbose && println("5/6 Too short response timeout (0.2s < 0.5s): ")
            # ctx_cl.response_timeout = (0, 200000)
            # rc,_ =  @test_logs((:warn, etimedout_reg),
            #                    read_registers(ctx_cl,
            #                                          UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT

            # # Wait for reply (0.2 + 0.4 > 0.5 s) and flush before continue
            # sleep(0.4)
            # modbus_flush!(ctx_cl)

            # verbose && println("6/6 Adequate response timeout (0.6s > 0.5s): ")
            # ctx_cl.response_timeout = (0, 600000)
            # rc,_ = read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1)
            # @test rc == 1
            # modbus_flush!(ctx_cl)
            # # Disable the byte timeout.
            #   The full response must be available in the 600ms interval
            # verbose && println("7/7 Disable byte timeout: ")
            # ctx_cl.response_timeout = (0, 0)
            # rc,_ = read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SLEEP_500_MS, 1)
            # @test rc == 1
            # # # Restore original response and byte timeout
            # ctx_cl.response_timeout = (old_response_to_sec, old_response_to_usec)
            # ctx_cl.byte_timeout = (old_byte_to_sec, old_byte_to_usec)
            # sleep(0.4)
            # modbus_flush!(ctx_cl)
            # # The test server is only able to test byte timeouts with the TCP
            # # backend
            # # Timeout of 3ms between bytes
            # verbose && println("1/2 Too small byte timeout (3ms < 5ms): ")
            # ctx_cl.byte_timeout = (0, 3000)
            # rc,_ = @test_logs((:warn, etimedout_reg),
            #                   read_registers(ctx_cl,
            #                                         UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS,
            #                                         1))
            # errn = errno()
            # @test rc == -1 && errn == Libc.ETIMEDOUT

            # # Wait remaing bytes before flushing
            # sleep(11 * 0.005)
            # modbus_flush!(ctx_cl)

            # # # Timeout of 7ms between bytes
            # ctx_cl.byte_timeout = (0, 7000)
            # verbose && println("2/2 Adapted byte timeout (7ms > 5ms): ")
            # rc,_ = read_registers(ctx_cl, UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS, 1)
            # @test rc == 1

            # # Restore original timeouts
            ctx_cl.response_timeout = (old_response_to_sec,
                                       old_response_to_usec)
            ctx_cl.byte_timeout = (old_byte_to_sec, old_byte_to_usec)
            sleep(0.4)
            modbus_flush!(ctx_cl)
        end
@testset "Bad response" begin
    verbose && println("* read_registers with invalid data: ")
    rc,_= @test_logs((:warn, r"Invalid data"),
                     read_registers(ctx_cl, UT_REGISTERS_ADDRESS,
                                    UT_REGISTERS_NB_SPECIAL))
    errn = errno()
    @test rc == -1 && errn == EMBBADDATA
    verbose && println("* read_registers at special address: ")
    rc,_ =  @test_logs((:warn, r"Slave device or server is busy"),
                       read_registers(ctx_cl, UT_REGISTERS_ADDRESS_SPECIAL,
                                      UT_REGISTERS_NB))
    errn = errno()
    @test rc == -1 && errn == EMBXSBUSY
end
disconnect(ctx_cl)
modbus_free!(ctx_cl)
@testset "Invalid initialization" begin
    einval_reg = Regex("$(Libc.strerror(Libc.EINVAL))")
    ctx_cl = @test_logs((:warn, einval_reg), RtuContext("", 1, :none, 8, 1))
    errn = errno()
    @test !ctx_cl.valid && errn == Libc.EINVAL
    
    ctx = @test_logs((:warn, einval_reg), RtuContext("/dev/dummy", 0,
                                                     :none, 8, 1))
    errn = errno()
    @test !ctx_cl.valid && errn == Libc.EINVAL
end
end
nothing
end

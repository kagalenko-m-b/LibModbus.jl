function tcp_write_byte(sockfd::Integer, buf::AbstractVector{UInt8}, idx)
    r_buf = Ref(buf, idx)
    ret = ccall(:write, Csize_t, (Cint, Ref{UInt8}, Csize_t),
                sockfd, r_buf, 1)
    LM._strerror(ret, "tcp_write_byte()")

    return ret
end

function server_main_loop(ctx::TcpContext, mb_mapping::Ptr{ModbusMapping}; verbose=false)
    header_length = ctx.header_length
    while true
        local ret_code,query
        while true
            ret_code,query = receive(ctx)
            # println("ret_code = $(ret_code)   query = $(query[1:ret_code])")
            # println("query_type $(query[hdr_length + 1])")
            ret_code == 0 || break
        end
        # do not close connection on bad CRC
        if ret_code < 0 && ret_code != EMBBADCRC
            break
        end
        if query[header_length + 1] == MODBUS_FC_READ_HOLDING_REGISTERS
            verbose && println("Read holding registers")
            if get_uint16(query, header_length + 4) == UT_REGISTERS_NB_SPECIAL
                verbose && println("Set an incorrect number of values")
                set_uint16!(query, header_length + 4, UT_REGISTERS_NB_SPECIAL - 1)
            elseif get_uint16(query, header_length + 2)  == UT_REGISTERS_ADDRESS_SPECIAL
                verbose && println("Reply to this special register address by an exception")
                reply_exception(ctx, query, LM.MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY)
            elseif get_uint16(query, header_length + 2) ==
                UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE
                raw_req = [0xFF, 0x03, 0x02, 0x00, 0x00]
                verbose && println("Reply with an invalid TID or slave")
                send_raw_request(ctx, raw_req)
            elseif get_uint16(query, header_length + 2) ==
                UT_REGISTERS_ADDRESS_SLEEP_500_MS
                verbose && println("Sleep 0.5 s before replying")
                sleep(0.5)
            elseif get_uint16(query, header_length + 2) ==
                UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS
                # Test low level only available in TCP mode
                # Catch the reply and send reply byte a byte
                req = [0x00, 0x1C, 0x00, 0x00, 0x00, 0x05 ,0xFF, 0x03, 0x02, 0x00, 0x00]
                w_s = ctx.socket
                # Copy TID
                req[2] = query[2]
                for i = 1:length(req)
                    sleep(0.005)
                    rc = tcp_write_byte(w_s, req, i)
                    rc > -1 || break
                end
            end
        end
        rc = reply(ctx, query, mb_mapping)
        verbose && println("rc = $(rc)")
        rc >= 0 || break
    end

    return Libc.errno()
end

function init_server_mapping()
    bits_tab = Vector{UInt8}(make_bitvector(UT_BITS_TAB, UT_BITS_NB))
    input_bits_tab = Vector{UInt8}(make_bitvector(UT_INPUT_BITS_TAB, UT_INPUT_BITS_NB))
    mb_mapping = modbus_mapping_new_start_address(
        UT_BITS_ADDRESS, UT_BITS_NB,
        UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
        UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
        UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB
    )
    
    for (k, x) in enumerate(UT_BITS_TAB)
        unsafe_store!(unsafe_load(mb_mapping).tab_bits, x, k)
    end
    for (k, x) in enumerate(input_bits_tab)
        unsafe_store!(unsafe_load(mb_mapping).tab_input_bits, x, k)
    end
    for (k, x) in enumerate(UT_INPUT_REGISTERS_TAB)
        unsafe_store!(unsafe_load(mb_mapping).tab_input_registers, x, k)
    end
    for (k, x) in enumerate(UT_REGISTERS_TAB)
        unsafe_store!(unsafe_load(mb_mapping).tab_registers, x, k)
    end

    return mb_mapping
end

function unit_test_server(ctx::TcpContext, mb_mapping::Ptr{ModbusMapping}; verbose=false)
    modbus_set_debug!(ctx, verbose)
    srv = tcp_listen(ctx, 1)
    srv > 0 || error("$(Libc.strerror(Libc.errno()))")
    sa = tcp_accept(ctx, srv)
    sa > 0 || error("$(Libc.strerror(Libc.errno()))")
    rc = server_main_loop(ctx, mb_mapping; verbose)
    verbose && println("Quit the loop: $(Libc.strerror(rc))")
    tcp_close(sa)
    tcp_close(srv)
end

function start_unit_test_server(ctx, mb_mapping; verbose=false)
    t = @task unit_test_server(ctx, mb_mapping; verbose)
    t.sticky = false;
    schedule(t)
end

module LibModbus

using LibModbus_jll

export ModbusMapping, TcpContext, RtuContext
export MODBUS_ERROR_RECOVERY_NONE, MODBUS_ERROR_RECOVERY_LINK
export MODBUS_ERROR_RECOVERY_PROTOCOL
export modbus_context_valid
export modbus_set_slave, modbus_get_slave, modbus_set_socket!, modbus_get_socket
export modbus_get_response_timeout, modbus_set_response_timeout, modbus_get_byte_timeout
export modbus_set_byte_timeout, modbus_set_error_recovery
export modbus_get_header_length, modbus_connect
export modbus_close, modbus_flush, modbus_free, modbus_set_debug
export modbus_read_bits, modbus_read_input_bits, modbus_read_registers
export modbus_read_input_registers, modbus_write_bit, modbus_write_register
export modbus_write_bits, modbus_write_registers, modbus_mask_write_register
export modbus_write_and_read_registers
export modbus_report_slave_id, modbus_mapping_new_start_address, modbus_mapping_new
export modbus_mapping_free!, modbus_receive, modbus_reply
export modbus_tcp_listen, modbus_tcp_accept, tcp_close
export modbus_rtu_set_serial_mode, modbus_rtu_get_serial_mode, modbus_rtu_set_rts
export modbus_get_rts, modbus_set_rts_delay, modbus_get_rts_delay

@enum Modbus_error_recovery_mode::Cint begin
    MODBUS_ERROR_RECOVERY_NONE = 0
    MODBUS_ERROR_RECOVERY_LINK = 1<<1
    MODBUS_ERROR_RECOVERY_PROTOCOL = 1<<2
end

mutable struct ModbusMapping
    nb_bits::Cint
    start_bits::Cint
    nb_input_bits::Cint
    start_input_bits::Cint
    nb_input_registers::Cint
    start_input_registers::Cint
    nb_registers::Cint
    start_registers::Cint
    tab_bits::Ptr{UInt8}
    tab_input_bits::Ptr{UInt8}
    tab_input_registers::Ptr{UInt16}
    tab_registers::Ptr{UInt16}
end

abstract type ModbusContext end
mutable struct Modbus_t end

struct TcpContext <: ModbusContext
    ip_address::String
    port::Int
    _ctx_ptr::Ref{Ptr{Modbus_t}}
    function TcpContext(ip_address::String, port::Integer)
        ctx_ptr = ccall((:modbus_new_tcp, libmodbus), Ptr{Modbus_t}, (Cstring, Cint),
                    ip_address, port)
        if ctx_ptr == C_NULL
            _strerror(-1, "TcpContext()")
        end
        ctx = new(ip_address, port, ctx_ptr)
    end
end
const MODBUS_TCP_MAX_ADU_LENGTH = 260

modbus_context_valid(ctx::ModbusContext) = ctx._ctx_ptr[] != C_NULL

function Base.show(io::IO, ctx::TcpContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str = modbus_context_valid(ctx) ? "ip $(ctx.ip_address), port $(ctx.port)" : "NULL"
    printstyled(io, "TcpContext($(str))"; color)
end

struct RtuContext <: ModbusContext
    device::String
    baud::Integer
    parity::Symbol
    data_bit::Integer
    stop_bit::Integer
    _ctx_ptr::Ref{Ptr{Modbus_t}}
    function RtuContext(
        device::String,
        baud::Integer,
        parity::Symbol,
        data_bit::Integer,
        stop_bit::Integer
        )
        if parity === :none
            prt = 'N'
        elseif parity === :even
            prt = 'E'
        elseif parity === :odd
            prt = 'O'
        else
            error("unknown parity value specified")
        end
        ctx_ptr = ccall((:modbus_new_rtu, libmodbus), Ptr{Modbus_t},
                    (Cstring, Cint, Cchar, Cint, Cint),
                    device, baud, prt, data_bit, stop_bit)
        if ctx_ptr == C_NULL
            _strerror(-1, "RtuContext()")
        end
        ctx = new(device, baud, parity, data_bit, stop_bit, ctx_ptr)
        return ctx
    end
end

function Base.show(io::IO, ctx::RtuContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str =  modbus_context_valid(ctx) ? "RtuContext(device $(ctx.device), baud $(ctx.baud), "*
    "parity $(ctx.parity)), data_bit $(ctx.data_bit), stop_bit $(ctx.stop_bit))" : "NULL"
    printstyled(io, str; color)
end

# Common for RTU and TCP contexts
function modbus_set_slave(ctx::ModbusContext, slave::Integer)
    ret = ccall((:modbus_set_slave, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], slave)
    _strerror(ret, "modbus_set_slave()")

    return ret
end

function modbus_get_slave(ctx::ModbusContext)
    ret = ccall((:modbus_get_slave, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_slave()")

    return ret
end

function modbus_set_socket!(ctx::ModbusContext, s::Integer)
    ret = ccall((:modbus_set_socket, libmodbus), Cint, (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_set_socket!()")

    return ret
end

function modbus_get_socket(ctx::ModbusContext)
    ret = ccall((:modbus_get_socket, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_socket()")

    return ret
end


function modbus_get_response_timeout(ctx::ModbusContext)
    to_sec = Ref{UInt32}()
    to_usec = Ref{UInt32}()
    ret = ccall((:modbus_get_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt32}, Ref{UInt32}),
                ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_get_response_timeout()")

    return ret,Int(to_sec[]),Int(to_usec[])
end

function modbus_set_response_timeout(ctx::ModbusContext,  to_sec::Integer, to_usec::Integer)
    ret = ccall((:modbus_set_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, UInt32, UInt32), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_set_response_timeout()")

    return ret
end

function modbus_get_byte_timeout(ctx::ModbusContext)
    to_sec = Ref{UInt32}(0)
    to_usec = Ref{UInt32}(0)
    ret = ccall((:modbus_get_byte_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt32}, Ref{UInt32}), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_get_byte_timeout()")

    return ret,Int(to_sec[]),Int(to_usec[])
 end

function modbus_set_byte_timeout(ctx::ModbusContext, to_sec::Integer, to_usec::Integer)
    ret = ccall((:modbus_set_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, UInt32, UInt32), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_set_byte_timeout()")

    return ret
end

# function modbus_get_indication_timeout(ctx::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

#   # int
# end

# function modbus_set_indication_timeout(ctx::ModbusContext, uint32_t to_sec, uint32_t to_usec)

#   # int
# end
function  modbus_set_error_recovery(ctx::ModbusContext, err_rec::Integer)
    ret = ccall((:modbus_set_error_recovery, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], Cint(err_rec))
    _strerror(ret, "modbus_set_error_recovery()")

    return ret
# int modbus_set_error_recovery(modbus_t *ctx, modbus_error_recovery_mode error_recovery)
end

function modbus_get_header_length(ctx::ModbusContext)
    ret = ccall((:modbus_get_header_length, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_header_length()")

    return ret
end

function modbus_connect(ctx::ModbusContext)
    ret = ccall((:modbus_connect, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_connect()")

    return ret
end

function modbus_close(ctx::ModbusContext)
    ccall((:modbus_close, libmodbus), Cvoid, (Ptr{Cvoid},), ctx._ctx_ptr[])
end

function modbus_free(ctx::ModbusContext)
    ccall((:modbus_free, libmodbus), Cvoid, (Ptr{Cvoid},), ctx._ctx_ptr[])
    ctx._ctx_ptr[] = C_NULL

    return nothing
end

function modbus_flush(ctx::ModbusContext)
    ret = ccall((:modbus_flush, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_flush()")

    return ret
end

function modbus_set_debug(ctx::ModbusContext, flag::Bool)
    ret = ccall((:modbus_set_debug, libmodbus), Cint, (Ptr{Cvoid},Cint),
                ctx._ctx_ptr[], flag)
    _strerror(ret, "modbus_set_debug()")

    return ret
end

function _strerror(return_code::Integer, message::AbstractString)
    err_no = Libc.errno()
    if return_code < 0
        return_code = err_no
        str = ccall((:modbus_strerror,libmodbus), Cstring, (Cint,), err_no)
        @warn "$(message): "*unsafe_string(str)
    end

    return nothing
end

function modbus_read_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_bits()")

    return ret,dest[1:ret]
end

function modbus_read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_input_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_input_bits()")

    return ret,dest[1:ret]
end

function modbus_read_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_registers()")
    ret <= 0 || ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return ret,dest[1:ret]
end

function modbus_read_input_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_input_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_input_registers()")
    ret <= 0 || ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return ret,dest[1:ret]
end

function modbus_write_bit(ctx::ModbusContext, coil_addr::Integer, status::Integer)
    ret = ccall((:modbus_write_bit, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), ctx._ctx_ptr[], coil_addr, status)
     _strerror(ret, "modbus_write_bit()")

    return ret
end

function modbus_write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer)
    ret = ccall((:modbus_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), ctx._ctx_ptr[], reg_addr, value)
    _strerror(ret, "modbus_write_register()")

    return ret
end

function modbus_write_bits(ctx::ModbusContext, addr::Integer, data::Vector{UInt8})
    nb = length(data)
    ret = ccall((:modbus_write_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "modbus_write_bits()")
    ret <= 0 || ret == nb || @warn "wrote $(ret) bits instead of $(nb)"

    return ret
end

function modbus_write_registers(ctx::ModbusContext, addr::Integer, data::Vector{UInt16})
    nb = length(data)
    ret = ccall((:modbus_write_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "modbus_write_registers()")
    ret <= 0 || ret == nb || @warn "wrote $(ret) registers instead of $(nb)"

    return ret
end

function modbus_mask_write_register(ctx::ModbusContext,
                                    addr::Integer,
                                    and_mask::UInt16,
                                    or_mask::UInt16)
    ret = ccall((:modbus_mask_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16, UInt16),
                ctx._ctx_ptr[], addr, and_mask, or_mask)
    _strerror(ret, "modbus_mask_write_register()")

    return ret
end

function modbus_write_and_read_registers(
    ctx::ModbusContext,
    write_addr::Integer,
    write_data::Vector{UInt16},
    read_addr::Integer,
    read_nb::Integer
    )
    write_nb = length(write_data)
    dest = Vector{UInt16}(undef, read_nb)
    ret = ccall((:modbus_write_and_read_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}, Cint, Cint, Ref{UInt16}),
                ctx._ctx_ptr[], write_addr, write_nb, write_data, read_addr, read_nb, dest)
    _strerror(ret, "modbus_write_and_read_registers()")
    ret <= 0 || ret == read_nb || @warn "read $(ret) registers instead of $(read_nb)"

    return ret,dest[1:ret]
end


function modbus_report_slave_id(ctx::ModbusContext, max_dest::Integer)
    dest = Vector{UInt8}(undef, max_dest)
    ret = ccall((:modbus_report_slave_id, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Ref{UInt8}), ctx._ctx_ptr[], max_dest, dest)
    _strerror(ret, "modbus_report_slave_id()")
    ret <= max_dest || @warn "$(ret) bytes of output truncated to $(max_dest)"

    return ret, dest #[1:min(max_dest, ret)]
end

function modbus_mapping_new_start_address(
    start_bits::Integer,
    nb_bits::Integer,
    start_input_bits::Integer,
    nb_input_bits::Integer,
    start_registers::Integer,
    nb_registers::Integer,
    start_input_registers::Integer,
    nb_input_registers::Integer
    )
    mbm_ptr = ccall((:modbus_mapping_new_start_address, libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint),
                    start_bits, nb_bits, start_input_bits, nb_input_bits,
                    start_registers, nb_registers, start_input_registers,nb_input_registers)
    _strerror(-Int(mbm_ptr == C_NULL), "modbus_mapping_new_start_address()")

    return mbm_ptr
end

function modbus_mapping_new(
    nb_bits::Integer,
    nb_input_bits::Integer,
    nb_registers::Integer,
    nb_input_registers::Integer
    )
    mbm_ptr = ccall((:modbus_mapping_new, libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint),
                    nb_bits, nb_input_bits, nb_registers, nb_input_registers)
    _strerror(-Int(mpm_ptr == C_NULL), "modbus_mapping_new()")

    return mbm_ptr
end

function modbus_free!(mbm_ptr::Ptr{ModbusMapping})
    ccall((:modbus_mapping_free, libmodbus), Cvoid,
          (Ptr{ModbusMapping},), mbm_ptr)
end

function modbus_receive(ctx::TcpContext)
    req = Vector{UInt8}(undef, MODBUS_TCP_MAX_ADU_LENGTH)
    ret = ccall((:modbus_receive, libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}),
                ctx._ctx_ptr[], req)
    _strerror(ret, "modbus_receive()")

    return ret,req
end

function modbus_reply(ctx::ModbusContext, req::Vector{UInt8}, mbm_ptr::Ptr{ModbusMapping})
    req_length = length(req)
    ret = ccall((:modbus_reply, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint, Ptr{Cvoid}),
                ctx._ctx_ptr[], req, req_length, mbm_ptr)
    _strerror(ret, "modbus_reply()")

    return ret
end

# TCP context
function modbus_tcp_listen(ctx::TcpContext, nb_connection::Integer)
    ret = ccall((:modbus_tcp_listen, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], nb_connection)
    _strerror(ret, "modbus_tcp_listen()")

    return ret
end

function modbus_tcp_accept(ctx::TcpContext, s::Cint)
    ret = ccall((:modbus_tcp_accept, libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_tcp_accept()")

    return ret
end

function tcp_close(sockfd::Integer)
    ret = ccall(:close, Cint,(Cint,), sockfd)
    _strerror(ret, "tcp_close()")

    return ret
end

# RTU context
const MODBUS_RTU_RS232 = 0
const MODBUS_RTU_RS485 = 1
const MODBUS_RTU_RTS_NONE =  0
const MODBUS_RTU_RTS_UP = 1
const MODBUS_RTU_RTS_DOWN = 2

function modbus_rtu_set_serial_mode(ctx::RtuContext, mode::Symbol)
    if mode is :RS485
        m_code = MODBUS_RTU_RS485
    elseif mode is :RS232
        m_code = MODBUS_RTU_RS232
    else
        error("unknown serial mode")
    end
    ret = ccall((:modbus_rtu_set_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], m_code)
    _strerror(ret, "modbus_rtu_set_serial_mode()")

    return ret
end

function modbus_rtu_get_serial_mode(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_serial_mode()")
    if ret == MODBUS_RTU_RS485
        mode = :RS485
    elseif ret == MODBUS_RTU_RS232
        mode = :RS232
    else
        @warn "unknown mode code returned by modbus_get_serial_mode()"
        mode = :Nothing
    end

  return mode
end

function modbus_rtu_set_rts(ctx::RtuContext, mode::Symbol)
    if mode is :RTS_NONE
        m_code = MODBUS_RTU_RTS_NONE
    elseif mode is :RTS_UP
        m_code = MODBUS_RTU_RTS_UP
    elseif mode is :RTS_DOWN
        m_code = MODBUS_RTU_RTS_DOWN
    else
        error("unknown rts mode")
    end
    ret = ccall((:modbus_rtu_set_rts_mode, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], m_code)
    _strerror(ret, "modbus_rtu_set_rts_mode()")

    return ret
end

function modbus_rtu_get_rts(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_rts()")
    if ret == MODBUS_RTU_RTS_NONE
        mode = :RTS_NONE
    elseif ret == MODBUS_RTU_RTS_UP
        mode = :RTS_UP
    elseif ret == MODBUS_RTU_RTS_DOWN
        mode = :RTS_DOWN
    else
        @warn "unknown RTS code returned by modbus_get_rts()"
        mode = :Nothing
    end

  return mode
end

function modbus_rtu_set_rts_delay(ctx::RtuContext, us::Int)
    ret = ccall((:modbus_rtu_set_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], us)
    _strerror(ret, "modbus_rtu_set_rts_delay()")

    return ret
end

function modbus_rtu_get_rts_delay(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_rts_delay()")

    return ret
end

end

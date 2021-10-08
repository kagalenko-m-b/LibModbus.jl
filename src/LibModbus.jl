module LibModbus

using LibModbus_jll

export ModbusMapping, TcpContext, RtuContext, modbus_context_valid
export set_slave, get_slave, set_socket!, get_socket, get_header_length, connect
export modbus_close, modbus_flush, modbus_free, set_debug
export read_bits, read_input_bits, read_registers, read_input_registers, write_register
export write_bits, write_registers
export report_slave_id, mapping_new_start_address, mapping_new
export mapping_free!, receive, reply
export tcp_listen, tcp_accept
export set_serial_mode, get_serial_mode, set_rts, get_rts, set_rts_delay, get_rts_delay

mutable struct ModbusMapping
    nb_bits::Cint
    start_bits::Cint
    nb_input_bits::Cint
    start_input_bits::Cint
    nb_input_registers::Cint
    start_input_registers::Cint
    nb_registers::Cint
    start_registers::Cint
    tab_bits::Ptr{UInt8};
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
            error("did not create create Modbus TCP context")
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
        stop_bit::Integer,
        _ctx_ptr::Ptr{Modbus_t}
        )
        if parity is :none
            prt = 'N'
        elseif parity is :even
            prt = 'E'
        elseif parity is :odd
            prt = 'O'
        else
            error("unknown parity value specified")
        end
        ctx_ptr = ccall((:modbus_new_rtu, libmodbus), Ptr{Modbus_t},
                    (Cstring, Cint, Cchar, Cint, Cint),
                    device, baud, prt, data_bit, stop_bit);
        if ctx_ptr == C_NULL
            _strerror(-1, "RtuContext()")
            error("did not create create Modbus RTU context")
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
function set_slave(ctx::ModbusContext, slave::Integer)
    ret = ccall((:modbus_set_slave, libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                ctx._ctx_ptr[], slave)
    _strerror(ret, "set_slave()")

    return ret
end

function get_slave(ctx::ModbusContext)
    ret = ccall((:modbus_get_slave, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_slave()")

    return ret
end

function set_socket!(ctx::ModbusContext, s::Integer)
    ret = ccall((:modbus_set_socket, libmodbus), Cint, (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], s)
    _strerror(ret, "set_socket!()")

    return ret
end

function get_socket(ctx::ModbusContext)
    ret = ccall((:modbus_get_socket, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_socket()")

    return ret
end

"""
function modbus_get_response_timeout(ctx::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end

function modbus_set_response_timeout(ctx::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end

function modbus_get_byte_timeout(ctx::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end

function modbus_set_byte_timeout(ctx::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end

function modbus_get_indication_timeout(ctx::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end

function modbus_set_indication_timeout(ctx::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end
"""
function get_header_length(ctx::ModbusContext)
    ret = ccall((:modbus_get_header_length, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_header_length()")

    return ret
end

function connect(ctx::ModbusContext)
    ret = ccall((:modbus_connect, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "connect()")

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

function set_debug(ctx::ModbusContext, flag::Bool)
    ret = ccall((:modbus_set_debug, libmodbus), Cint, (Ptr{Cvoid},Cint), ctx._ctx_ptr[], flag)
    _strerror(ret, "set_debug()")

    return ret
end

function _strerror(return_code::Integer, message::AbstractString)
    err_no = Libc.errno()
    if return_code < 0
        return_code = err_no
        str = ccall((:modbus_strerror,libmodbus), Cstring, (Cint,), err_no)
        @error "$(message): "*unsafe_string(str)
    end

    return nothing
end

function read_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "read_bits()")

    return ret
end

function read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_input_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "read_input_bits()")

    return ret
end

function read_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "read_registers()")
    ret <= 0 || ret == nb || @error "read $(ret) registers instead of $(nb)"

    return ret,dest[1:ret]
end

function read_input_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_input_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "read_input_registers()")
    ret == nb || @error "read $(ret) registers instead of $(nb)"

    return dest[1:ret]
end

function write_bit(ctx::ModbusContext, coil_addr::Integer, status::Integer)
    ret = ccall((:modbus_write_bit, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), ctx._ctx_ptr[], coil_addr, status)
     _strerror(ret, "write_bit()")

    return ret
end

function write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer)
    ret = ccall((:modbus_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), ctx._ctx_ptr[], reg_addr, value)
    _strerror(ret, "write_register()")

    return ret
end

function write_bits(ctx::ModbusContext, addr::Integer, data::Vector{UInt8})
    nb = length(data)
    ret = ccall((:modbus_write_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, data)
    _strerror("write_bits()", Libc.errno())
    ret <= 0 || ret == nb || @error "wrote $(ret) bits instead of $(nb)"

    return ret
end

function write_registers(ctx::ModbusContext, addr::Integer, data::Vector{UInt16})
    nb = length(data)
    ret = ccall((:modbus_write_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "write_registers()")
    ret <= 0 || ret == nb || @error "wrote $(ret) registers instead of $(nb)"

    return ret
end

"""
function modbus_mask_write_register(ctx::ModbusContext, addr::Integer, uint16_t and_mask, uint16_t or_mask)

  # int
end

function modbus_write_and_read_registers(ctx::ModbusContext, write::Integer_addr, write::Integer_nb, const uint16_t *src, read::Integer_addr, read::Integer_nb, uint16_t *dest)

  # int
end
"""

function report_slave_id(ctx::ModbusContext, max_dest::Integer)
    dest = Vector{UInt8}(undef, max_dest)
    ret = ccall((:modbus_report_slave_id, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Ref{UInt8}), ctx._ctx_ptr[], max_dest, dest)
    _strerror(ret, "report_slave_id()")
    ret <= max_dest || @error "$(ret) bytes of output truncated to $(max_dest)"

    return dest[1:min(max_dest, ret)]
end

function mapping_new_start_address(
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

function mapping_new(
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

function receive(ctx::TcpContext)
    req = Vector{UInt8}(undef, MODBUS_TCP_MAX_ADU_LENGTH)
    ret = ccall((:modbus_receive, libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}), ctx._ctx_ptr[], req)
    _strerror(ret, "receive()")

    return ret,req
end

function reply(ctx::ModbusContext, req::Vector{UInt8}, mbm_ptr::Ptr{ModbusMapping})
    req_length = length(req)
    ret = ccall((:modbus_reply, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint, Ptr{Cvoid}),
                ctx._ctx_ptr[], req, req_length, mbm_ptr)
    _strerror(ret, "reply()")

    return ret
end

# TCP context
function tcp_listen(ctx::TcpContext, nb_connection::Integer)
    ret = ccall((:modbus_tcp_listen, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], nb_connection)
    _strerror(ret, "tcp_listen()")

    return ret
end

function tcp_accept(ctx::TcpContext, s::Cint)
    ret = ccall((:modbus_tcp_accept, libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                ctx._ctx_ptr[], s)
    _strerror(ret, "tcp_accept()")

    return ret
end

# RTU context
const MODBUS_RTU_RS232 = 0
const MODBUS_RTU_RS485 = 1
const MODBUS_RTU_RTS_NONE =  0
const MODBUS_RTU_RTS_UP = 1
const MODBUS_RTU_RTS_DOWN = 2

function set_serial_mode(ctx::RtuContext, mode::Symbol)
    if mode is :RS485
        m_code = MODBUS_RTU_RS485
    elseif mode is :RS232
        m_code = MODBUS_RTU_RS232
    else
        error("unknown serial mode")
    end
    ret = ccall((:modbus_rtu_set_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], m_code)
    _strerror(ret, "set_serial_mode()")

    return ret
end

function get_serial_mode(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_serial_mode()")
    if ret == MODBUS_RTU_RS485
        mode = :RS485
    elseif ret == MODBUS_RTU_RS232
        mode = :RS232
    else
        @error "unknown mode code returned by modbus_get_serial_mode()"
        mode = :Nothing
    end

  return mode
end

function set_rts(ctx::RtuContext, mode::Symbol)
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
    _strerror(ret, "set_rts_mode()")

    return ret
end

function get_rts(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_rts()")
    if ret == MODBUS_RTU_RTS_NONE
        mode = :RTS_NONE
    elseif ret == MODBUS_RTU_RTS_UP
        mode = :RTS_UP
    elseif ret == MODBUS_RTU_RTS_DOWN
        mode = :RTS_DOWN
    else
        @error "unknown RTS code returned by modbus_get_rts()"
        mode = :Nothing
    end

  return mode
end

function set_rts_delay(ctx::RtuContext, us::Int)
    ret = ccall((:modbus_rtu_set_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], us)
    _strerror(ret, "set_rts_delay()")

    return ret
end

function get_rts_delay(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "get_rts_delay()")

    return ret
end

end

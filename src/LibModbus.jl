module LibModbus

export TcpContext, RtuContext
export set_slave, get_slave, set_socket!, get_socket, modbus_connect, modbus_close
export modbus_flush, set_debug
export read_bits, read_input_bits, read_registers, read_input_registers, write_register
export write_bits, write_registers
export report_slave_id, modbus_mapping_new_start_address, modbus_mapping_new
export modbus_mapping_free, modbus_receive, modbus_reply
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
    valid::Ref{Bool}
    _ctx::Ptr{Modbus_t}
    function TcpContext(ip_address::String, port::Integer)
        ctx = ccall((:modbus_new_tcp, :libmodbus), Ptr{Modbus_t}, (Cstring, Cint),
                    ip_address, port)
        if ctx == C_NULL
            modbus_strerror(-1, "TcpContext()")
            error("did not create create Modbus TCP context")
        end
        mc = new(ip_address, port, true, ctx)
    end
end
const MODBUS_TCP_MAX_ADU_LENGTH = 260
function Base.show(io::IO, mc::TcpContext)
    color = mc.valid[] ? :green : :red
    printstyled(io, "TcpContext(ip $(mc.ip_address), port $(mc.port))"; color)
end

struct RtuContext <: ModbusContext
    device::String
    baud::Integer
    parity::Symbol
    data_bit::Integer
    stop_bit::Integer
    valid::Ref{Bool}
    _ctx::Ptr{Modbus_t}
    function RtuContext(
        device::String,
        baud::Integer,
        parity::Symbol,
        data_bit::Integer,
        stop_bit::Integer,
        valid::Ref{Bool},
        _ctx::Ptr{Modbus_t}
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
        ctx = ccall((:modbus_new_rtu, :libmodbus), Ptr{Modbus_t},
                    (Cstring, Cint, Cchar, Cint, Cint),
                    device, baud, prt, data_bit, stop_bit);
        if ctx == C_NULL
            modbus_strerror(-1, "RtuContext()")
            error("did not create create Modbus RTU context")
        end
        mc = new(device, baud, parity, data_bit, stop_bit, true, _ctx)
        return mc
    end
end

function Base.show(io::IO, mc::RtuContext)
    color = mc.valid[] ? :green : :red
    str = "RtuContext(device $(mc.device), baud $(mc.baud), parity $(mc.parity)), "*
        "data_bit $(mc.data_bit), stop_bit $(mc.stop_bit))"
    printstyled(io, str; color)
end

# Common for RTU and TCP contexts
function set_slave(mc::ModbusContext, slave::Integer)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_set_slave, :libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                mc._ctx, slave)
    modbus_strerror(ret, "set_slave()")

    return ret
end

function get_slave(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_get_slave, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "get_slave()")

    return ret
end

function set_socket!(mc::ModbusContext, s::Integer)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_set_socket, :libmodbus), Cint, (Ptr{Cvoid}, Cint), mc._ctx, s)
    modbus_strerror(ret, "set_socket()")

    return ret
end

function get_socket(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_get_socket, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "get_socket()")

    return ret
end

"""
function modbus_get_response_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_set_response_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_get_byte_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_set_byte_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_get_indication_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_set_indication_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_get_header_length(mc::ModbusContext)
    mc.valid[] || error("invalid context")

  # int
end
"""

function modbus_connect(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_connect, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "modbus_connect()")

    return ret
end

function modbus_close(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    modbus_flush(mc)
    ccall((:modbus_close, :libmodbus), Cvoid, (Ptr{Cvoid},), mc._ctx)
end

function modbus_free(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    ccall((:modbus_free, :libmodbus), Cvoid, (Ptr{Cvoid},), mc._ctx)
    mc.valid[] = false

    return nothing
end

function modbus_flush(mc::ModbusContext)
    mc.valid[] || error("invalid context")
    ccall((:modbus_flush, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
end

function set_debug(mc::ModbusContext, flag::Bool)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_set_debug, :libmodbus), Cint, (Ptr{Cvoid},Cint), mc._ctx, flag)
    modbus_strerror(ret, "set_debug()")

    return ret
end

function modbus_strerror(return_code::Integer, message::AbstractString)
    errno = Libc.errno()
    if return_code < 0
        str = ccall((:modbus_strerror,:libmodbus), Cstring, (Cint,), errno)
        @warn "$(message): "*unsafe_string(str)
    end

    return nothing
end

function read_bits(mc::ModbusContext, addr::Integer, nb::Integer)
    mc.valid[] || error("invalid context")
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), mc._ctx, addr, nb, dest)
    modbus_strerror(ret, "read_bits()")

    return ret
end

function read_input_bits(mc::ModbusContext, addr::Integer, nb::Integer)
    mc.valid[] || error("invalid context")
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_input_bits, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), mc._ctx, addr, nb, dest)
    modbus_strerror(ret, "read_input_bits()")

    return ret
end

function read_registers(mc::ModbusContext, addr::Integer, nb::Integer)
    mc.valid[] || error("invalid context")
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_registers, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, dest)
    modbus_strerror(ret, "read_registers()")
    ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return dest[1:ret]
end

function read_input_registers(mc::ModbusContext, addr::Integer, nb::Integer)
    mc.valid[] || error("invalid context")
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_input_registers, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, dest)
    modbus_strerror(ret, "read_input_registers()")
    ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return dest[1:ret]
end

function write_bit(mc::ModbusContext, coil_addr::Integer, status::Integer)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_write_bit, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), mc._ctx, coil_addr, status)
     modbus_strerror(ret, "write_bit()")

    return ret
end

function write_register(mc::ModbusContext, reg_addr::Integer, value::Integer)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_write_register, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), mc._ctx, reg_addr, value)
    modbus_strerror(ret, "write_register()")

    return ret
end

function write_bits(mc::ModbusContext, addr::Integer, data::Vector{UInt8})
    mc.valid[] || error("invalid context")
    nb = length(data)
    ret = ccall((:modbus_write_bits, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), mc._ctx, addr, nb, data)
    modbus_strerror("write_bits()", Libc.errno())
    ret == nb || @warn "wrote $(ret) bits instead of $(nb)"

    return ret
end

function write_registers(
    mc::ModbusContext, addr::Integer, data::AbstractVector{UInt16}
    )
    mc.valid[] || error("invalid context")
    nb = length(data)
    ret = ccall((:modbus_write_registers, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, data)
    modbus_strerror(ret, "write_registers()")
    ret == nb || @warn "wrote $(ret) registers instead of $(nb)"

    return ret
end

"""
function modbus_mask_write_register(mc::ModbusContext, addr::Integer, uint16_t and_mask, uint16_t or_mask)
    mc.valid[] || error("invalid context")

  # int
end

function modbus_write_and_read_registers(mc::ModbusContext, write::Integer_addr, write::Integer_nb, const uint16_t *src, read::Integer_addr, read::Integer_nb, uint16_t *dest)
    mc.valid[] || error("invalid context")

  # int
end
"""

function report_slave_id(mc::ModbusContext, max_dest::Integer)
    mc.valid[] || error("invalid context")
    dest = Vector{UInt8}(undef, max_dest)
    ret = ccall((:modbus_report_slave_id, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Ref{UInt8}), mc._ctx, max_dest, dest)
    modbus_strerror(ret, "report_slave_id()")
    ret <= max_dest || @warn "$(ret) bytes of output truncated to $(max_dest)"

    return dest[1:min(max_dest, ret)]
end

function modbus_mapping_new_start_address(
    start_bits::Integer,
    nb_bits::Integer,
    start_input_bits::Integer,
    nb_input_bits::Integer,
    start_registers::Integer,
    nb_registers::Integer,
    start_input_registers::Integer,
    nb_input_registers::Integer)
    mc.valid[] || error("invalid context")

    mbm_ptr = ccall((:modbus_mapping_new_start_address, :libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint),
                    start_bits, nb_bits, start_input_bits, nb_input_bits,
                    start_registers, nb_registers, start_input_registers,nb_input_registers)
    modbus_strerror(-Int(mpm_ptr == C_NULL), "modbus_mapping_new_start_address()")

    return mbm_ptr
end

function modbus_mapping_new(
    nb_bits::Integer,
    nb_input_bits::Integer,
    nb_registers::Integer,
    nb_input_registers::Integer)
    mc.valid[] || error("invalid context")

    mbm_ptr = ccall((:modbus_mapping_new, :libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint),
                    nb_bits, nb_input_bits, nb_registers, nb_input_registers)
    modbus_strerror(-Int(mpm_ptr == C_NULL), "modbus_mapping_new()")

    return mbm_ptr
end

function modbus_mapping_free(mbm_ptr::Ptr{ModbusMapping})
    mc.valid[] || error("invalid context")
    ccall((:modbus_mapping_free, :libmodbus), Cvoid,
                    (Ptr{ModbusMapping}, ), mbm_ptr)
end

function modbus_receive(mc::TcpContext)
    mc.valid[] || error("invalid context")
    req = Vector{UInt8}(undef, MODBUS_TCP_MAX_ADU_LENGTH)
    ret = ccall((:modbus_receive, :libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}), mc._ctx, req)
    modbus_strerror(ret, "modbus_receive()")

    return req[1:ret]
end

function modbus_reply(mc::ModbusContext, req::Vector{UInt8}, mbm_ptr::Ptr{ModbusMapping})
    mc.valid[] || error("invalid context")
    req_length = length(req)
    ret = ccall((:modbus_reply, :libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint, Ptr{Cvoid}),
                mc._ctx, req, req_length, mbm_ptr)
    modbus_strerror(ret, "modbus_reply()")

    return ret
end

# TCP context
function tcp_listen(mc::TcpContext, nb_connection::Integer)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_tcp_listen, :libmodbus), Cint, (Ptr{Cvoid}, Cint),
                mc._ctx, nb_connection)
    modbus_strerror(ret, "tcp_listen()")

    return ret
end

function tcp_accept(mc::TcpContext, s::Ref{Cint})
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_tcp_accept, :libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}), mc._ctx, s)
    modbus_strerror(ret, "modbus_accept()")

    return ret
end

# RTU context
const MODBUS_RTU_RS232 = 0
const MODBUS_RTU_RS485 = 1
const MODBUS_RTU_RTS_NONE =  0
const MODBUS_RTU_RTS_UP = 1
const MODBUS_RTU_RTS_DOWN = 2

function set_serial_mode(mc::RtuContext, mode::Symbol)
    mc.valid[] || error("invalid context")
    if mode is :RS485
        m_code = MODBUS_RTU_RS485
    elseif mode is :RS232
        m_code = MODBUS_RTU_RS232
    else
        error("unknown serial mode")
    end
    ret = ccall((:modbus_rtu_set_serial_mode, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint), mc._ctx, m_code)
    modbus_strerror(ret, "set_serial_mode()")

    return ret
end

function get_serial_mode(mc::RtuContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_rtu_get_serial_mode, :libmodbus), Cint,
                (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "get_serial_mode()")
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

function set_rts(mc::RtuContext, mode::Symbol)
    mc.valid[] || error("invalid context")
    if mode is :RTS_NONE
        m_code = MODBUS_RTU_RTS_NONE
    elseif mode is :RTS_UP
        m_code = MODBUS_RTU_RTS_UP
    elseif mode is :RTS_DOWN
        m_code = MODBUS_RTU_RTS_DOWN
    else
        error("unknown rts mode")
    end
    ret = ccall((:modbus_rtu_set_rts_mode, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint), mc._ctx, m_code)
    modbus_strerror(ret, "set_rts_mode()")

    return ret
end

function get_rts(mc::RtuContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_rtu_get_rts, :libmodbus), Cint,
                (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "get_rts()")
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

function set_rts_delay(mc::RtuContext, us::Int)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_rtu_set_rts_delay, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint), mc._ctx, us)
    modbus_strerror(ret, "set_rts_delay()")

    return ret
end

function get_rts_delay(mc::RtuContext)
    mc.valid[] || error("invalid context")
    ret = ccall((:modbus_rtu_get_rts_delay, :libmodbus), Cint,
                (Ptr{Cvoid},), mc._ctx)
    modbus_strerror(ret, "get_rts_delay()")

    return ret
end

end

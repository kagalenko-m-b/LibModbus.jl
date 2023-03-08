"""
Idea from https://discourse.julialang.org/t/i-have-vector-uint8-i-need-bitvector/2286/5
"""
function make_bitvector(v::AbstractVector{T}) where T<:Union{UInt8,UInt16,UInt32,UInt64}
    siz = sizeof(v)
    bv = falses(siz<<3)
    unsafe_copyto!(reinterpret(Ptr{UInt8}, pointer(bv.chunks)), pointer(v), siz)
    bv
end
make_bitvector(v, nb::Integer) = make_bitvector(v)[1:nb]
get_uint16(arr::Vector{UInt8}, k::Integer) = reinterpret(UInt16, view(arr, k + 1:-1:k))[]
function set_uint16!(arr::Vector{UInt8}, k::Integer, val::Integer)
    v_k = view(arr, k + 1:-1:k)
    v_k .= reinterpret(UInt8, [UInt16(val)])
end


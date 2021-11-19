using Distributed
using Test

(@isdefined verbose) || (verbose = false)

srv_proc = addprocs(1)[]

@everywhere begin
    using Pkg
    Pkg.activate("LibModbus")
    Pkg.instantiate()
    using LibModbus
    include("unit_test_constants.jl")
    include("unit_test_functions.jl")
end

include("unit_test_client.jl")

fetch(@spawnat srv_proc @eval Main mb_mapping=init_server_mapping())
fetch(@spawnat srv_proc @eval Main ctx_server = TcpContext("127.0.0.1", 1502))

remote_do(()->start_unit_test_server(ctx_server, mb_mapping), srv_proc)


unit_test_client(verbose)

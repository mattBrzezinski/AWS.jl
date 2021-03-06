# This file is auto-generated by AWSMetadata.jl
using AWS
using AWS.AWSServices: s3outposts
using AWS.Compat
using AWS.UUIDs

"""
    create_endpoint(outpost_id, security_group_id, subnet_id)
    create_endpoint(outpost_id, security_group_id, subnet_id, params::Dict{String,<:Any})

S3 on Outposts access points simplify managing data access at scale for shared datasets in
Amazon S3 on Outposts. S3 on Outposts uses endpoints to connect to Outposts buckets so that
you can perform actions within your virtual private cloud (VPC).  This action creates an
endpoint and associates it with the specified Outpost.   Related actions include:
DeleteEndpoint     ListEndpoints

# Arguments
- `outpost_id`: The ID of the AWS Outpost.
- `security_group_id`: The ID of the security group to use with the endpoint.
- `subnet_id`: The ID of the subnet in the selected VPC.

"""
create_endpoint(OutpostId, SecurityGroupId, SubnetId; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("POST", "/S3Outposts/CreateEndpoint", Dict{String, Any}("OutpostId"=>OutpostId, "SecurityGroupId"=>SecurityGroupId, "SubnetId"=>SubnetId); aws_config=aws_config)
create_endpoint(OutpostId, SecurityGroupId, SubnetId, params::AbstractDict{String}; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("POST", "/S3Outposts/CreateEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("OutpostId"=>OutpostId, "SecurityGroupId"=>SecurityGroupId, "SubnetId"=>SubnetId), params)); aws_config=aws_config)

"""
    delete_endpoint(endpoint_id, outpost_id)
    delete_endpoint(endpoint_id, outpost_id, params::Dict{String,<:Any})

S3 on Outposts access points simplify managing data access at scale for shared datasets in
Amazon S3 on Outposts. S3 on Outposts uses endpoints to connect to Outposts buckets so that
you can perform actions within your virtual private cloud (VPC).  This action deletes an
endpoint.   Related actions include:    CreateEndpoint     ListEndpoints

# Arguments
- `endpoint_id`: The ID of the end point.
- `outpost_id`: The ID of the AWS Outpost.

"""
delete_endpoint(endpointId, outpostId; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("DELETE", "/S3Outposts/DeleteEndpoint", Dict{String, Any}("endpointId"=>endpointId, "outpostId"=>outpostId); aws_config=aws_config)
delete_endpoint(endpointId, outpostId, params::AbstractDict{String}; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("DELETE", "/S3Outposts/DeleteEndpoint", Dict{String, Any}(mergewith(_merge, Dict{String, Any}("endpointId"=>endpointId, "outpostId"=>outpostId), params)); aws_config=aws_config)

"""
    list_endpoints()
    list_endpoints(params::Dict{String,<:Any})

S3 on Outposts access points simplify managing data access at scale for shared datasets in
Amazon S3 on Outposts. S3 on Outposts uses endpoints to connect to Outposts buckets so that
you can perform actions within your virtual private cloud (VPC).  This action lists
endpoints associated with the Outpost.   Related actions include:    CreateEndpoint
DeleteEndpoint

# Optional Parameters
Optional parameters can be passed as a `params::Dict{String,<:Any}`. Valid keys are:
- `"maxResults"`: The max number of endpoints that can be returned on the request.
- `"nextToken"`: The next endpoint requested in the list.
"""
list_endpoints(; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("GET", "/S3Outposts/ListEndpoints"; aws_config=aws_config)
list_endpoints(params::AbstractDict{String}; aws_config::AbstractAWSConfig=global_aws_config()) = s3outposts("GET", "/S3Outposts/ListEndpoints", params; aws_config=aws_config)

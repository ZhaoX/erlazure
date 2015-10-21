%% Copyright (c) 2015 - 2015, Xin Zhao
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions are met:
%%
%% * Redistributions of source code must retain the above copyright notice,
%% this list of conditions and the following disclaimer.
%% * Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%% * Neither the name of erlazure nor the names of its contributors may be used to
%% endorse or promote products derived from this software without specific
%% prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%% ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
%% LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
%% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
%% SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
%% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
%% CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
%% ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.

%% ============================================================================
%% Azure Storage API without Starting a Process.
%% ============================================================================

-module(erlazure_lib_r15).
-author("Xin Zhao").

-include("../include/erlazure.hrl").
-include("../include/erlazure_lib.hrl").

%% Blob API
-export([put_block_blob/4, put_block_blob/5]).
-export([get_blob/3, get_blob/4]).
-export([default_config/0]).

default_config() ->
        #azure_config{account = "", key = ""}.

put_block_blob(Container, Name, Data, Config) ->
        put_block_blob(Container, Name, Data, Config, []).
put_block_blob(Container, Name, Data, Config, Options) ->
        ServiceContext = #service_context{ service = ?blob_service,
                                           api_version = ?blob_service_ver,
                                           account = Config#azure_config.account,
                                           key = Config#azure_config.key },
        ReqOptions = [{method, put},
                      {path, lists:concat([Container, "/", Name])},
                      {body, Data},
                      {params, [{blob_type, block_blob}] ++ Options}],
        ReqContext = new_req_context(?blob_service, Config#azure_config.account, get_req_param_specs(), ReqOptions),
        ReqContext1 = ReqContext#req_context{ content_type = "application/octet-stream" },

        {?http_created, _Body} = execute_request(ServiceContext, ReqContext1),
        {ok, created}.


get_blob(Container, Blob, Config) ->
        get_blob(Container, Blob, Config, []).
get_blob(Container, Blob, Config, Options) ->
        ServiceContext = #service_context{ service = ?blob_service,
                                           api_version = ?blob_service_ver,
                                           account = Config#azure_config.account,
                                           key = Config#azure_config.key },
        ReqOptions = [{path, lists:concat([Container, "/", Blob])},
                      {params, Options}],
        ReqContext = new_req_context(?blob_service, Config#azure_config.account, get_req_param_specs(), ReqOptions),

        {Code, Body} = execute_request(ServiceContext, ReqContext),
        case Code of
          ?http_ok ->
            {ok, Body};
          ?http_partial_content->
            {ok, Body}
        end.

%%--------------------------------------------------------------------
%% Private functions
%%--------------------------------------------------------------------

-spec execute_request(service_context(), req_context()) -> {non_neg_integer(), binary()}.
execute_request(ServiceContext = #service_context{}, ReqContext = #req_context{}) ->
        DateHeader = if (ServiceContext#service_context.service =:= ?table_service) ->
                          {"Date", httpd_util:rfc1123_date()};
                        true ->
                          {"x-ms-date", httpd_util:rfc1123_date()}
                     end,

        Headers =  [DateHeader,
                    {"x-ms-version", ServiceContext#service_context.api_version},
                    {"Host", get_host(ServiceContext#service_context.service,
                                      ServiceContext#service_context.account)}],

        Headers1 = if (ReqContext#req_context.method =:= put orelse
                       ReqContext#req_context.method =:= post) andalso
                      (ReqContext#req_context.body =/= []) ->
                        ContentHeaders = [{"Content-Type", ReqContext#req_context.content_type},
                                          {"Content-Length", integer_to_list(ReqContext#req_context.content_length)}],
                        lists:append([Headers, ContentHeaders, ReqContext#req_context.headers]);

                      true ->
                        lists:append([Headers, ReqContext#req_context.headers])
                   end,

        AuthHeader = {"Authorization", get_shared_key(ServiceContext#service_context.service,
                                                      ServiceContext#service_context.account,
                                                      ServiceContext#service_context.key,
                                                      ReqContext#req_context.method,
                                                      ReqContext#req_context.path,
                                                      ReqContext#req_context.parameters,
                                                      Headers1)},

        %% Fiddler
        %% httpc:set_options([{ proxy, {{"localhost", 9999}, []}}]),

        Response = httpc:request(ReqContext#req_context.method,
                                 erlazure_http:create_request(ReqContext, [AuthHeader | Headers1]),
                                 [{version, "HTTP/1.1"}],
                                 [{sync, true}, {body_format, binary}, {headers_as_is, true}]),
        case Response of
          {ok, {{_, Code, _}, _, Body}}
          when Code >= 200, Code =< 206 ->
               {Code, Body};

          {ok, {{_, _, _}, _, Body}} ->
               throw(Body)
        end.

get_shared_key(Service, Account, Key, HttpMethod, Path, Parameters, Headers) ->
        SignatureString = get_signature_string(Service, HttpMethod, Headers, Account, Path, Parameters),
        "SharedKey " ++ Account ++ ":" ++ base64:encode_to_string(sign_string(Key, SignatureString)).

get_signature_string(Service, HttpMethod, Headers, Account, Path, Parameters) ->
        SigStr1 = erlazure_http:verb_to_str(HttpMethod) ++ "\n" ++
                  get_headers_string(Service, Headers),

        SigStr2 = if (Service =:= ?queue_service) orelse (Service =:= ?blob_service) ->
                    SigStr1 ++ canonicalize_headers(Headers);
                    true -> SigStr1
                  end,
        SigStr2 ++ canonicalize_resource(Account, Path, Parameters).

get_headers_string(Service, Headers) ->
        FoldFun = fun(HeaderName, Acc) ->
                    case lists:keyfind(HeaderName, 1, Headers) of
                      {HeaderName, Value} -> lists:concat([Acc, Value, "\n"]);
                      false -> lists:concat([Acc, "\n"])
                    end
                  end,
        lists:foldl(FoldFun, "", get_header_names(Service)).

-spec sign_string(base64:ascii_string(), string()) -> binary().
sign_string(Key, StringToSign) ->
        hmac_sha256:mac(base64:decode(Key), list_to_binary(StringToSign)).

build_uri_base(Service, Account) ->
        lists:concat(["https://", get_host(Service, Account), "/"]).

get_host(Service, Account) ->
        %lists:concat([Account, ".", erlang:atom_to_list(Service), ".core.windows.net"]).
        lists:concat([Account, ".", erlang:atom_to_list(Service), ".core.chinacloudapi.cn"]).

-spec canonicalize_headers([string()]) -> string().
canonicalize_headers(Headers) ->
        MSHeaderNames = [HeaderName || {HeaderName, _} <- Headers, string:str(HeaderName, "x-ms-") =:= 1],
        SortedHeaderNames = lists:sort(MSHeaderNames),
        FoldFun = fun(HeaderName, Acc) ->
                    {_, Value} = lists:keyfind(HeaderName, 1, Headers),
                    lists:concat([Acc, HeaderName, ":", Value, "\n"])
                  end,
        lists:foldl(FoldFun, "", SortedHeaderNames).

canonicalize_resource(Account, Path, []) ->
        lists:concat(["/", Account, "/", Path]);

canonicalize_resource(Account, Path, Parameters) ->
        SortFun = fun({ParamNameA, ParamValA}, {ParamNameB, ParamValB}) ->
                    ParamNameA ++ ParamValA =< ParamNameB ++ ParamValB
                 end,
        SortedParameters = lists:sort(SortFun, Parameters),
        [H | T] = SortedParameters,
        "/" ++ Account ++ "/" ++ Path ++ combine_canonical_param(H, "", "", T).

combine_canonical_param({Param, Value}, Param, Acc, []) ->
        add_value(Value, Acc);

combine_canonical_param({Param, Value}, _PreviousParam, Acc, []) ->
        add_param_value(Param, Value, Acc);

combine_canonical_param({Param, Value}, Param, Acc, ParamList) ->
        [H | T] = ParamList,
        combine_canonical_param(H, Param, add_value(Value, Acc), T);

combine_canonical_param({Param, Value}, _PreviousParam, Acc, ParamList) ->
        [H | T] = ParamList,
        combine_canonical_param(H, Param, add_param_value(Param, Value, Acc), T).

add_param_value(Param, Value, Acc) ->
        Acc ++ "\n" ++ string:to_lower(Param) ++ ":" ++ Value.

add_value(Value, Acc) ->
        Acc ++ "," ++ Value.

get_header_names(?blob_service) ->
        get_header_names(?queue_service);

get_header_names(?queue_service) ->
        ["Content-Encoding",
         "Content-Language",
         "Content-Length",
         "Constent-MD5",
         "Content-Type",
         "Date",
         "If-Modified-Since",
         "If-Match",
         "If-None-Match",
         "If-Unmodified-Since",
         "Range"];

get_header_names(?table_service) ->
        ["Content-MD5",
         "Content-Type",
         "Date"].

new_req_context(Service, Account, ParamSpecs, Options) ->
        Method = proplists:get_value(method, Options, get),
        Path = proplists:get_value(path, Options, ""),
        Body = proplists:get_value(body, Options, ""),
        Headers = proplists:get_value(headers, Options, []),
        Params = proplists:get_value(params, Options, []),
        AddHeaders = if (Service =:= ?table_service) ->
                        case lists:keyfind("Accept", 1, Headers) of
                          false -> [{"Accept", "application/json;odata=fullmetadata"}];
                          _ -> []
                        end;
                        true -> []
                     end,

        ReqParams = get_req_uri_params(Params, ParamSpecs),
        ReqHeaders = lists:append([Headers, AddHeaders, get_req_headers(Params, ParamSpecs)]),

        #req_context{ address = build_uri_base(Service, Account),
                      path = Path,
                      method = Method,
                      body = Body,
                      content_length = erlazure_http:get_content_length(Body),
                      parameters = ReqParams,
                      headers = ReqHeaders }.

get_req_headers(Params, ParamSpecs) ->
        get_req_params(Params, ParamSpecs, header).

get_req_uri_params(Params, ParamSpecs) ->
        get_req_params(Params, ParamSpecs, uri).

get_req_params(Params, ParamSpecs, Type) ->
        ParamDefs = orddict:filter(fun(_, Value) -> Value#param_spec.type =:= Type end, ParamSpecs),
        FoldFun = fun({_ParamName, ""}, Acc) ->
                      Acc;

                      ({ParamName, ParamValue}, Acc) ->
                        case orddict:find(ParamName, ParamDefs) of
                          {ok, Value} -> [{Value#param_spec.name, (Value#param_spec.parse_fun)(ParamValue)} | Acc];
                          error -> Acc
                        end
                  end,
        lists:foldl(FoldFun, [], Params).

get_req_param_specs() ->
        ProcessFun = fun(Spec=#param_spec{}, Dictionary) ->
                        orddict:store(Spec#param_spec.id, Spec, Dictionary)
                    end,

        CommonParamSpecs = lists:foldl(ProcessFun, orddict:new(), get_req_common_param_specs()),
        BlobParamSpecs = lists:foldl(ProcessFun, CommonParamSpecs, erlazure_blob:get_request_param_specs()),

        lists:foldl(ProcessFun, BlobParamSpecs, erlazure_queue:get_request_param_specs()).

get_req_common_param_specs() ->
        [#param_spec{ id = comp, type = uri, name = "comp" },
         #param_spec{ id = ?req_param_timeout, type = uri, name = "timeout" },
         #param_spec{ id = ?req_param_maxresults, type = uri, name = "maxresults" },
         #param_spec{ id = ?req_param_prefix, type = uri, name = "prefix" },
         #param_spec{ id = ?req_param_include, type = uri, name = "include" },
         #param_spec{ id = ?req_param_marker, type = uri, name = "marker" }].

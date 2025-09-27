use anyhow::{bail, Context, Result};
use host_api::{
    host_api_server::{HostApiRpc, HostApiServer},
    GetSealingKeyRequest, GetSealingKeyResponse, HostInfo, Notification,
};
use ra_rpc::{CallContext, RemoteEndpoint, RpcCall};
use rocket_vsock_listener::VsockEndpoint;

use crate::app::App;
use key_provider_client::host::get_key;
// 为虚拟机内部的 Guest Agent 提供宿主机服务的 gRPC 接口
pub struct HostApiHandler {
    endpoint: VsockEndpoint,        // 请求来源的 VSock 端点（CID + 端口）
    app: App,                       // VMM 应用状态 
}
// VSock 连接验证
impl RpcCall<App> for HostApiHandler {
    type PrpcService = HostApiServer<Self>;

    fn construct(context: CallContext<'_, App>) -> Result<Self> {
        // // 严格验证：只接受来自 VSock 的连接
        let Some(RemoteEndpoint::Vsock { cid, port }) = context.remote_endpoint else {
            bail!("invalid remote endpoint: {:?}", context.remote_endpoint);
        };
        Ok(Self {
            endpoint: VsockEndpoint { cid, port },
            app: context.state.clone(),
        })
    }
}

impl HostApiRpc for HostApiHandler {
    // 主机信息查询
    async fn info(self) -> Result<HostInfo> {
        let host_info = HostInfo {
            name: "Dstack VMM".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        Ok(host_info)
    }
    // 虚拟机事件通知
    async fn notify(self, request: Notification) -> Result<()> {
        self.app
            .vm_event_report(self.endpoint.cid, &request.event, request.payload)
    }
    // 获取密封密钥
    async fn get_sealing_key(self, request: GetSealingKeyRequest) -> Result<GetSealingKeyResponse> {
        let key_provider = &self.app.config.key_provider;
        // 检查密钥提供者是否启用
        if !key_provider.enabled {
            bail!("Key provider is not enabled");
        }
        // 调用外部密钥提供者服务
        let response = get_key(request.quote, key_provider.address, key_provider.port)
            .await
            .context("Failed to get sealing key from key provider")?;

        Ok(GetSealingKeyResponse {
            encrypted_key: response.encrypted_key,
            provider_quote: response.provider_quote,
        })
    }
}

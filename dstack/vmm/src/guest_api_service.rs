use crate::App as AppState;
use anyhow::Result;
use guest_api::{
    proxied_guest_api_server::{ProxiedGuestApiRpc, ProxiedGuestApiServer},
    GuestInfo, Id, ListContainersResponse, NetworkInformation, SystemInfo,
};
use ra_rpc::{CallContext, RpcCall};
use std::ops::Deref;
// 实现了一个 代理模式 的 gRPC 服务，将外部的 API 请求转发给虚拟机内部的 Guest Agent。
pub struct GuestApiHandler {
    state: AppState,            // 应用状态
}

impl Deref for GuestApiHandler {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl RpcCall<AppState> for GuestApiHandler {
    type PrpcService = ProxiedGuestApiServer<Self>; // 声明这是一个代理服务器

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(Self {
            state: context.state.clone(),
        })
    }
}

impl ProxiedGuestApiRpc for GuestApiHandler {
    // 获取虚拟机基础信息
    async fn info(self, request: Id) -> Result<GuestInfo> {
        // 路由：根据 VM ID 找到对应的 Guest Agent 客户端
        // 转发：调用相同名称的方法
        // 等待：异步等待虚拟机内部响应
        self.guest_agent_client(&request.id)?.info().await
    }
    // 获取系统信息（CPU、内存、磁盘等）
    async fn sys_info(self, request: Id) -> Result<SystemInfo> {
        self.guest_agent_client(&request.id)?.sys_info().await
    }
    // 获取网络信息（IP地址、网络接口等）
    async fn network_info(self, request: Id) -> Result<NetworkInformation> {
        self.guest_agent_client(&request.id)?.network_info().await
    }
    // 列出虚拟机内运行的容器
    async fn list_containers(self, request: Id) -> Result<ListContainersResponse> {
        self.guest_agent_client(&request.id)?
            .list_containers()
            .await
    }
    // 关闭虚拟机
    async fn shutdown(self, request: Id) -> Result<()> {
        self.guest_agent_client(&request.id)?.shutdown().await
    }
}

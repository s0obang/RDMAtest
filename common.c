//common.c
#include "common.h"

//rdma 컨택스트 초기화
void build_context(struct rdma_context *ctx, struct rdma_cm_id *id) {
    // device
    struct ibv_device **device_list = ibv_get_device_list(NULL);
    ctx->device = device_list[0]; 
    ctx->verbs = ibv_open_device(ctx->device); //장치열고
    ibv_free_device_list(device_list); //장치목록 해제

    // resource
    //rdma_cm_id는 **RDMA 연결을 관리하는 식별자(Connection Manager Identifier)**다.
		//RDMA에서 클라이언트와 서버 간의 연결(Connection) 및 이벤트(Event)를 관리하는 핵심 구조체다.
    //rdma_cm_id를 사용하여 RDMA QP(Queue Pair) 및 네트워크 정보를 설정할 수 있다.
    ctx->pd = ibv_alloc_pd(id->verbs); //보호도메인 설정
    if (!ctx->pd) {
        perror("ibv_alloc_pd");
        exit(EXIT_FAILURE);
	}
    //id->context = (void *)malloc(sizeof(struct rdma_context));
		//완료 채널 생성
    ctx->comp_channel = ibv_create_comp_channel(id->verbs); 
    if (!ctx->comp_channel) {
        perror("ibv_create_comp_channel");
        exit(EXIT_FAILURE);
	}
		//완료 큐 생성
    ctx->cq = ibv_create_cq(id->verbs, CQ_CAPACITY, NULL, ctx->comp_channel, 0);
    if (!ctx->cq) {
        perror("ibv_create_cq");
        exit(EXIT_FAILURE);
	}
		//완료이벤트 대기대기
		//ctx->cq: 완료 큐
		//0: 모든 완료 이벤트 감지
		//1: Solicited 이벤트만 감지
		//성공하면 0, 실패하면 -1 반환
    if (ibv_req_notify_cq(ctx->cq, 0)) {
        perror("ibv_req_notify_cq");
        exit(EXIT_FAILURE);
    }
}
//큐페어 속성 설정부
//ibv_qp_init_attr: QP의 초기화 속성을 저장할 구조체 포인터
//struct rdma_context *ctx: RDMA 관련 정보를 저장한 컨텍스트 구조체 포인터
void build_qp_attr(struct ibv_qp_init_attr *attr, struct rdma_context *ctx) {

    memset(attr, 0, sizeof(*attr));
    attr->qp_type = IBV_QPT_RC; // Reliable Connection (RC) 타입 설정

    attr->cap.max_send_wr = MAX_WR;
    attr->cap.max_recv_wr = MAX_WR;
    attr->cap.max_send_sge = MAX_SGE;
    attr->cap.max_recv_sge = MAX_SGE;

    if (!ctx->cq) {
        fprintf(stderr, "Completion Queue (CQ) is not initialized.\n");
        exit(EXIT_FAILURE);
    }
	//송신(Send)과 수신(Receive) 작업의 완료 큐(Completion Queue, CQ)를 동일하게 설정한다.
	//즉, 송/수신 작업이 완료되면 같은 CQ에서 이벤트를 처리하게 된다.

    attr->send_cq = ctx->cq;
    attr->recv_cq = ctx->cq;
//**SRQ(Shared Receive Queue)**를 사용하지 않겠다는 의미.
//SRQ는 여러 QP가 공유할 수 있는 수신 큐를 제공하는 기능.
//여기서는 QP마다 별도의 수신 큐를 사용하도록 설정.
    attr->srq = NULL;
    attr->sq_sig_all = 0;
}


// QP 상태 전환 함수

void transition_qp_to_init(struct ibv_qp* qp) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = 1; // 사용 중인 RDMA 포트
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    if (ibv_modify_qp(qp, &attr, flags)) {
        perror("Failed to set QP to INIT");
        exit(EXIT_FAILURE);
    }
    printf("[QP] Transitioned to INIT state.\n");
}

void transition_qp_to_rtr(struct ibv_qp* qp, uint32_t remote_qp_num, uint32_t remote_lid) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qp_num;  // 상대방 QP 번호
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;

    struct ibv_ah_attr ah_attr;
    memset(&ah_attr, 0, sizeof(ah_attr));
    ah_attr.dlid = remote_lid; // 상대방 LID
    ah_attr.sl = 0; // 서비스 레벨
    ah_attr.src_path_bits = 0;
    ah_attr.port_num = 1; // RDMA 포트 번호

    attr.ah_attr = ah_attr;

    int flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
        IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    if (ibv_modify_qp(qp, &attr, flags)) {
        perror("Failed to set QP to RTR");
        exit(EXIT_FAILURE);
    }
    printf("[QP] Transitioned to RTR state.\n");
}

void transition_qp_to_rts(struct ibv_qp* qp) {
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &attr, flags)) {
        perror("Failed to set QP to RTS");
        exit(EXIT_FAILURE);
    }
    printf("[QP] Transitioned to RTS state.\n");
}
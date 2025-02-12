//common.h

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <rdma/rdma_cma.h> //rdma관련
#include <rdma/rdma_verbs.h> //rdma관련

//RDMA는 litte endian/big endian에서 일관된 바이트 순서를 유지해야함
//그래서 리틀엔디안이면 바이트 스왑 수행
#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) __builtin_bswap64(x)
#define ntohll(x) __builtin_bswap64(x)
#endif //endian.h


// Constants
#define KEY_VALUE_SIZE 256 //키-값 저장하는곳
#define BUFFER_SIZE (KEY_VALUE_SIZE * 3) //버퍼 크기
#define SERVER_PORT 20079
#define TIMEOUT_IN_MS 500
#define CQ_CAPACITY 16 // complete queue크기

//이 아래 두개 뭔지 모름 검색
#define MAX_SGE 1 //Scatter-Gather Elements(SGE) 최대 수
#define MAX_WR 16 //Work Requests(WR)의 최대 개수

//메모리 공유 위한 정보 저장용 구조체 
struct pdata { 
    uint64_t buf_va; // ?
    uint32_t buf_rkey; // remote key
    uint32_t qp_num;   // QP 번호 추가
    union ibv_gid gid; // GID 추가 (16바이트)
};

//메세지 타입들. one-sided만 잇내
enum msg_type {
    MSG_PUT,
    MSG_GET
};

//키값 쌍 (연결리스트인듯)
struct kv_pair {
    char key[KEY_VALUE_SIZE];
    char value[KEY_VALUE_SIZE];
    struct kv_pair *next;
};

//최종적으로 RDMA에 전달할 메세지 형식!!!
struct message {
    enum msg_type type;
    struct kv_pair kv;
};

//RDMA 연결을 설정하기 위한 필수 요소
//ibv_로 시작하는 구조체나 함수들은 libibverbs 라이브러리에서 제공하는 API를 의미한다. 
//Verbs API는 RDMA 장치와 직접 상호작용하는 저수준 API로, RDMA 장치를 제어하고
//메모리 등록, 전송, 큐페어 설정 등을 수행할 수 있다.
struct rdma_context {
    struct ibv_device *device; //사용할 rdma장치
    struct ibv_context *verbs; //장치 핸들
    struct ibv_pd *pd;//protection domain(보호 도메인)
    struct ibv_comp_channel *comp_channel; //완료 알ㄹ림용 채널
    struct ibv_cq *cq;//완료 큐
    struct ibv_cq *evt_cq; //?? 
    //-> 이벤트 기반 모델에서 사용된대.  rdma이벤트 발생시 이벤트 받음
    struct ibv_qp *qp;//큐페어
    struct ibv_mr *send_mr, *recv_mr; // 송-수신 메모리 영역(리전)
};
//RDMA 컨텍스트를 설정하는 함수
void build_context(struct rdma_context *ctx, struct rdma_cm_id *id);
//큐페어(QP) 속성을 설정하는 함수
void build_qp_attr(struct ibv_qp_init_attr *attr, struct rdma_context *ctx);

// QP 상태 전환 함수
void transition_qp_to_init(struct ibv_qp* qp);
void transition_qp_to_rtr(struct ibv_qp* qp, uint32_t remote_qp_num, union ibv_gid* remote_gid);
void transition_qp_to_rts(struct ibv_qp* qp);

#endif // COMMON_H

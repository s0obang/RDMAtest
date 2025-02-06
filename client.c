//client.c
#include "common.h"

/* RDMA resource */
static struct rdma_context ctx;
static struct rdma_cm_id *id = NULL;
static struct rdma_event_channel *ec = NULL;
static struct rdma_cm_event *event = NULL;
static struct ibv_qp_init_attr qp_attr;

void *cq_context;
static struct pdata rep_pdata;

struct ibv_recv_wr recv_wr, *bad_recv_wr = NULL;
struct ibv_send_wr send_wr, *bad_send_wr = NULL;
struct ibv_sge send_sge, recv_sge;
struct ibv_wc wc;
static char *send_buffer = NULL, *recv_buffer = NULL;

static void setup_connection(const char *server_ip);
static void pre_post_recv_buffer();
static void connect_server();

int on_connect();
void post_send_message();
int receive_response();
int wait_for_completion();
int post_and_wait(struct ibv_send_wr *wr, const char *operation_name);

void cleanup(struct rdma_cm_id *id);


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    setup_connection(argv[1]);
    pre_post_recv_buffer();
    connect_server();
    on_connect();

    return 0;
}

static void setup_connection(const char *server_ip) {
    int ret;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(server_ip);

    ec = rdma_create_event_channel();
    if (!ec) {
        perror("rdma_create_event_channel");
        exit(EXIT_FAILURE);
    }

    ret = rdma_create_id(ec, &id, NULL, RDMA_PS_TCP);
    if (ret) {
        perror("rdma_create_id");
        exit(EXIT_FAILURE);
    }

    ret = rdma_resolve_addr(id, NULL, (struct sockaddr *)&addr, TIMEOUT_IN_MS);
    if (ret) {
        perror("rdma_resolve_addr");
        exit(EXIT_FAILURE);
    }

    ret = rdma_get_cm_event(ec, &event);
    if (ret) {
        perror("rdma_get_cm_event");
        exit(EXIT_FAILURE);
    }

    ret = rdma_ack_cm_event(event);
    if (ret) {
        perror("rdma_ack_cm_event");
        exit(EXIT_FAILURE);
    }

    build_context(&ctx, id);
    build_qp_attr(&qp_attr, &ctx);

    printf("Creating QP...\n");
    ret = rdma_create_qp(id, ctx.pd, &qp_attr);
    if (ret) {
        perror("rdma_create_qp");
        exit(EXIT_FAILURE);
    }
    printf("Queue Pair created: %p\n\n", (void*)id->qp);
    ctx.qp = id->qp;

    ret = rdma_resolve_route(id, TIMEOUT_IN_MS);
    if (ret) {
        perror("rdma_resolve_route");
        exit(EXIT_FAILURE);
    }

    ret = rdma_get_cm_event(ec, &event);
    if (ret) {
        perror("rdma_get_cm_event");
        exit(EXIT_FAILURE);
    }

    ret = rdma_ack_cm_event(event);
    if (ret) {
        perror("rdma_ack_cm_event");
        exit(EXIT_FAILURE);
    }
}


static void pre_post_recv_buffer() {
    static int buffer_initialized = 0;

    if (!buffer_initialized) {
        recv_buffer = calloc(2, sizeof(struct message));  // 메시지 두 개를 받을 수 있도록 설정
        if (!recv_buffer) {
            perror("Failed to allocate memory for receive buffer");
            exit(EXIT_FAILURE);
        }

        ctx.recv_mr = ibv_reg_mr(ctx.pd, recv_buffer, BUFFER_SIZE, 
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

        if (!ctx.recv_mr) {
            perror("Failed to register memory region");
            exit(EXIT_FAILURE);
        }

        buffer_initialized = 1;  // 버퍼 초기화 완료
    }

    recv_sge.addr = (uintptr_t)recv_buffer;
    recv_sge.length = sizeof(struct message);  // 한 번에 한 메시지를 처리한다고 가정
    recv_sge.lkey = ctx.recv_mr->lkey;

    memset(&recv_wr, 0, sizeof(recv_wr));
    recv_wr.wr_id = 0;
    recv_wr.sg_list = &recv_sge;
    recv_wr.num_sge = 1;

    if (ibv_post_recv(id->qp, &recv_wr, &bad_recv_wr)) {
        perror("Failed to post receive work request");
        exit(EXIT_FAILURE);
    }
    printf("Memory registered at address %p with LKey %u\n", recv_buffer, ctx.recv_mr->lkey);
}


static void connect_server() {
    struct rdma_conn_param conn_param;

    rep_pdata.buf_va = (uintptr_t)recv_buffer;
    rep_pdata.buf_rkey = htonl(ctx.recv_mr->rkey);

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.initiator_depth = 3;
    conn_param.responder_resources = 3;
    conn_param.retry_count = 3;
    conn_param.private_data = &rep_pdata; 
    conn_param.private_data_len = sizeof(rep_pdata);

    printf("Connecting...\n");

    // **QP 상태 전환 추가**
    transition_qp_to_init(id->qp);
    transition_qp_to_rtr(id->qp, rep_pdata.buf_va, rep_pdata.buf_rkey);
    transition_qp_to_rts(id->qp);

    if (rdma_connect(id, &conn_param)) {
        perror("Failed to connect to remote host");
        exit(EXIT_FAILURE);
    }

    if (rdma_get_cm_event(ec, &event)) {
        perror("Failed to get cm event");
        exit(EXIT_FAILURE);
    }
    printf("Connection established.\n");

    memcpy(&rep_pdata, event->param.conn.private_data, sizeof(rep_pdata));
    printf("Received Server Memory at address %p with RKey %u\n\n",(void *)rep_pdata.buf_va, ntohl(rep_pdata.buf_rkey));

    if (rdma_ack_cm_event(event)) {
        perror("Failed to acknowledge cm event");
        exit(EXIT_FAILURE);
    }
    printf("The client is connected successfully. \n\n");
}

int on_connect() {
    char command[256];
    struct message msg_send;

    //send_buffer = (char *)malloc(sizeof(struct message));
    send_buffer = (char *)calloc(2, sizeof(struct message));
    if (!send_buffer) {
        perror("Failed to allocate memory for send buffer");
        exit(EXIT_FAILURE);
    }

    ctx.send_mr = ibv_reg_mr(ctx.pd, send_buffer, sizeof(struct message), IBV_ACCESS_LOCAL_WRITE 
        | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    
    if (!ctx.send_mr) {
        fprintf(stderr, "Failed to register client metadata buffer.\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Enter command ( put k v / get k ): ");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            fprintf(stderr, "Error reading command\n");
            continue;
        }
        command[strcspn(command, "\n")] = '\0'; 

        char *cmd = strtok(command, " ");

        if (strcmp(cmd, "put") == 0) {
            char *key = strtok(NULL, " ");
            char *value = strtok(NULL, "");

            strncpy(msg_send.kv.key, key, sizeof(msg_send.kv.key));
            msg_send.kv.key[KEY_VALUE_SIZE - 1] = '\0';
            //printf("Key size Packet size: %lu bytes\n\n", sizeof(msg_send.kv.key));

            strncpy(msg_send.kv.value, value, sizeof(msg_send.kv.value));
            msg_send.kv.value[KEY_VALUE_SIZE - 1] = '\0';
            msg_send.type = MSG_PUT;
            //printf("value size Packet size: %lu bytes\n\n", sizeof(msg_send.kv.value));

            printf("msg key: %s, msg value: %s\n", msg_send.kv.key, msg_send.kv.value);

        } else if (strcmp(cmd, "get") == 0) {

            char *key = strtok(NULL, "");

            strncpy(msg_send.kv.key, key, sizeof(msg_send.kv.key));
            msg_send.kv.key[KEY_VALUE_SIZE - 1] = '\0';
            msg_send.kv.value[0] = '\0'; 
            msg_send.type = MSG_GET;

            printf("msg key: %s, msg value: %s\n", msg_send.kv.key, msg_send.kv.value);
        } else {
            printf("Invalid command\n");
            continue;
        }

        memcpy(send_buffer, &msg_send, sizeof(struct message));
    
        post_send_message();
    }

    cleanup(id);
    return 0;
}

void post_send_message() {
    struct message *msg_send = (struct message *)send_buffer;

    send_sge.addr = (uintptr_t)send_buffer;
    send_sge.length = sizeof(struct message);
    send_sge.lkey = ctx.send_mr->lkey;

    send_wr.wr_id = 2;
    send_wr.sg_list = &send_sge;
    send_wr.num_sge = 1;
    send_wr.send_flags = IBV_SEND_SIGNALED;

    //send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.wr.rdma.rkey = ntohl(rep_pdata.buf_rkey); 
	send_wr.wr.rdma.remote_addr = ntohll(rep_pdata.buf_va); 

    struct message *msg_in_buffer = (struct message *)send_buffer;
    printf("\nsend_buffer content:\n");
    printf("Type: %d\n", msg_in_buffer->type);
    printf("Key: %s\n", msg_in_buffer->kv.key);
    printf("Value: %s\n\n", msg_in_buffer->kv.value);

    // if (post_and_wait(&send_wr, "RDMA Write") != 0) {
    //     exit(EXIT_FAILURE);
    // }

    send_wr.opcode = IBV_WR_SEND;
    //send_sge.length = sizeof(struct message);

    pre_post_recv_buffer();
    //sleep(5);

    if (post_and_wait(&send_wr, "Send") != 0) {
        exit(EXIT_FAILURE);
    }
    if (receive_response() != 0) {
        fprintf(stderr, "Failed to receive response\n");
        exit(EXIT_FAILURE);
    }
}

int post_and_wait(struct ibv_send_wr *wr, const char *operation_name) {
    if (ibv_post_send(id->qp, wr, &bad_send_wr)) {
        fprintf(stderr, "Failed to post %s work request: %s\n", operation_name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (wait_for_completion() != 0) {
        fprintf(stderr, "%s operation failed\n", operation_name);
        exit(EXIT_FAILURE);
    }

    printf("%s completed successfully\n", operation_name);
    return 0;
}

int wait_for_completion() {
    struct ibv_wc wc;
    int ret;

    while ((ret = ibv_poll_cq(ctx.cq, 1, &wc)) == 0);

    if (ret < 0) {
        fprintf(stderr, "Failed to poll CQ: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "WR failed with status %s\n", ibv_wc_status_str(wc.status));
        exit(EXIT_FAILURE);
    }

    return 0;
}

int receive_response() {
    if (wait_for_completion() != 0) {
        fprintf(stderr, "Failed to receive response\n");
        exit(EXIT_FAILURE);
    }

    struct message *response = (struct message *)recv_buffer;
    printf("\nrecv_buffer content:\n");
    printf("Type: %d\n", response->type);
    printf("Key: %s\n", response->kv.key);
    printf("Value: %s\n\n", response->kv.value);


    if (response->type == MSG_GET) {
        printf("GET Received response: Key: %s, Value: %s\n\n", response->kv.key, response->kv.value);
    } else if (response->type == MSG_PUT) {
        printf("PUT Response value: %s\n\n", response->kv.value);
    }

    return 0;
}

void cleanup(struct rdma_cm_id *id) {

    if (send_buffer) {
        free(send_buffer);
        send_buffer = NULL;
    }

    if (recv_buffer) {
        free(recv_buffer);
        recv_buffer = NULL;
    }

    if (ctx.recv_mr) {
        ibv_dereg_mr(ctx.recv_mr);
        ctx.recv_mr = NULL;
    }

    if (ctx.send_mr) {
        ibv_dereg_mr(ctx.send_mr);
        ctx.send_mr = NULL;
    }

    if (ctx.qp) {
        rdma_destroy_qp(id);
        ctx.qp = NULL;
    }

    if (ctx.cq) {
        ibv_destroy_cq(ctx.cq);
        ctx.cq = NULL;
    }

    if (ctx.comp_channel) {
        ibv_destroy_comp_channel(ctx.comp_channel);
        ctx.comp_channel = NULL;
    }

    if (ctx.pd) {
        ibv_dealloc_pd(ctx.pd);
        ctx.pd = NULL;
    }

    if (id) {
        rdma_destroy_id(id);
        id = NULL;
    }

    if (ec) {
        rdma_destroy_event_channel(ec);
        ec = NULL;
    }
}
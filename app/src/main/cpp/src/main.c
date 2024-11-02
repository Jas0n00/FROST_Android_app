#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../headers/setup.h"
#include "../headers/signing.h"

// Function to initialize participants
participant* initialize_participants(int threshold, int participants) {
    participant* p = (participant*)malloc(participants * sizeof(participant));
    if (p == NULL) {
        printf("Memory allocation for participants failed\n");
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < participants; i++) {
        p[i].index = i;
        p[i].threshold = threshold;
        p[i].participants = participants;
        p[i].pub_commit = NULL;
        p[i].rcvd_commit_head = NULL;
        p[i].rcvd_sec_share_head = NULL;
    }

    return p;
}

// Function to initialize public commitments
pub_commit_packet** initialize_pub_commits(participant* p, int participants) {
    pub_commit_packet** pub_commits = (pub_commit_packet**)malloc(participants * sizeof(pub_commit_packet*));
    if (pub_commits == NULL) {
        printf("Memory allocation for public commitments failed\n");
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < participants; i++) {
        pub_commits[i] = init_pub_commit(&p[i]);
    }

    return pub_commits;
}

// Function to initialize the threshold set
participant* initialize_threshold_set(int threshold, participant* p, int* indices) {
    participant* threshold_set = (participant*)malloc(threshold * sizeof(participant));
    if (threshold_set == NULL) {
        printf("Memory allocation for threshold set failed\n");
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < threshold; i++) {
        threshold_set[i] = p[indices[i]];
    }

    return threshold_set;
}

// Function to perform signing process
void perform_signing(int threshold, int participants, const char* message, int* indices) {
    participant* p = initialize_participants(threshold, participants);
    if (p == NULL) return;

    pub_commit_packet** pub_commits = initialize_pub_commits(p, participants);
    if (pub_commits == NULL) {
        free(p);
        return;
    }

    // Simulate broadcasting the public commitments to all other participants
    for (int i = 0; i < participants; i++) {
        for (int j = 0; j < participants; j++) {
            if (i != j) {
                accept_pub_commit(&p[i], pub_commits[j]);
            }
        }
    }

    // Initialize and exchange secret shares
    for (int i = 0; i < participants; i++) {
        BIGNUM* self_share = init_sec_share(&p[i], p[i].index);
        accept_sec_share(&p[i], p[i].index, self_share);

        for (int j = 0; j < participants; j++) {
            if (i != j) {
                BIGNUM* sec_share = init_sec_share(&p[i], p[j].index);
                accept_sec_share(&p[j], p[i].index, sec_share);
            }
        }
    }

    // Generate keys for all participants
    for (int i = 0; i < participants; i++) {
        gen_keys(&p[i]);
    }

    // Create threshold set
    participant* threshold_set = initialize_threshold_set(threshold, p, indices);
    if (threshold_set == NULL) {
        free(p);
        free(pub_commits);
        return;
    }

    // Initialize public share commitments for chosen participants
    aggregator agg = { .threshold = threshold, .rcvd_pub_share_head = NULL };
    pub_share_packet** pub_shares = (pub_share_packet**)malloc(threshold * sizeof(pub_share_packet*));
    if (pub_shares == NULL) {
        printf("Memory allocation for public shares failed\n");
        free(p);
        free(pub_commits);
        free(threshold_set);
        return;
    }

    for (int i = 0; i < threshold; i++) {
        pub_shares[i] = init_pub_share(&threshold_set[i]);
        accept_pub_share(&agg, pub_shares[i]);
    }

    // Calculate message length manually
    int m_len = 0;
    while (message[m_len] != '\0') {
        m_len++;
    }

    // Generate and accept tuple packets
    tuple_packet* agg_tuple = init_tuple_packet(&agg, message, m_len, threshold_set, threshold);
    for (int i = 0; i < threshold; i++) {
        accept_tuple(&threshold_set[i], agg_tuple);
    }

    // Generate signature shares
    for (int i = 0; i < threshold; i++) {
        BIGNUM* sig_share = init_sig_share(&threshold_set[i]);
        accept_sig_share(&agg, sig_share, threshold_set[i].index);
    }

    // Finalize the signature
    signature_packet sig = signature(&agg);
    printf("\nSignature: ");
    BN_print_fp(stdout, sig.signature);
    printf("\nHash: ");
    BN_print_fp(stdout, sig.hash);
    printf("\n");

    // Verify the signature
    verify_signature(&sig, message, p[0].public_key);

    // Clean up dynamically allocated memory
    free(p);
    free(pub_commits);
    free(pub_shares);
    free(threshold_set);
}

// Entry point for JNI
void execute_signing(int threshold, int participants, const char* message, int* indices) {
    perform_signing(threshold, participants, message, indices);
}

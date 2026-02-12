#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/core.h"

static volatile sig_atomic_t g_stop_requested = 0;

static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        g_stop_requested = 1;
    }
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("main: sigaction(SIGINT)");
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("main: sigaction(SIGTERM)");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *config_path = "aegis-agent.conf";
    agent_config_t cfg;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [config_path]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        config_path = argv[1];
    }

    if (install_signal_handlers() != 0) {
        return EXIT_FAILURE;
    }

    if (config_load(config_path, &cfg) != 0) {
        fprintf(stderr, "main: failed to load config from %s\n", config_path);
        return EXIT_FAILURE;
    }

    if (agent_loop_run(&cfg, &g_stop_requested) != 0) {
        fprintf(stderr, "main: agent loop exited with error\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

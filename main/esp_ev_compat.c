#include "esp_ev_compat.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <sys/select.h>
#include <string.h>

static const char *TAG = "ESP_EV_COMPAT";

// Define custom event base for our libev compatibility layer
ESP_EVENT_DEFINE_BASE(LIBEV_EVENTS);
enum {
    LIBEV_IO_EVENT,
    LIBEV_TIMER_EVENT,
    LIBEV_BREAK_EVENT
};

// Global default event loop
static ev_loop default_loop;
ev_loop *EV_DEFAULT = &default_loop;

// Task that monitors file descriptors using select()
static void io_monitor_task(void *arg) {
    ev_loop *loop = (ev_loop *)arg;
    fd_set read_fds, write_fds;
    struct timeval tv;
    
    while (loop->running) {
        // Prepare FD sets
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int max_fd = -1;
        
        // Lock io_mutex to safely access watchers
        xSemaphoreTake(loop->io_mutex, portMAX_DELAY);
        
        // Set up FDs to monitor
        for (int i = 0; i < MAX_IO_WATCHERS; i++) {
            if (loop->io_watchers[i] && loop->io_watchers[i]->active) {
                ev_io *w = loop->io_watchers[i];
                if (w->events & EV_READ)
                    FD_SET(w->fd, &read_fds);
                if (w->events & EV_WRITE)
                    FD_SET(w->fd, &write_fds);
                if (w->fd > max_fd)
                    max_fd = w->fd;
            }
        }
        
        xSemaphoreGive(loop->io_mutex);
        
        if (max_fd >= 0) {
            // Set short timeout for select
            tv.tv_sec = 0;
            tv.tv_usec = 50000; // 50ms
            
            int ret = select(max_fd + 1, &read_fds, &write_fds, NULL, &tv);
            
            if (ret > 0) {
                xSemaphoreTake(loop->io_mutex, portMAX_DELAY);
                
                for (int i = 0; i < MAX_IO_WATCHERS; i++) {
                    if (loop->io_watchers[i] && loop->io_watchers[i]->active) {
                        ev_io *w = loop->io_watchers[i];
                        int revents = 0;
                        
                        if ((w->events & EV_READ) && FD_ISSET(w->fd, &read_fds))
                            revents |= EV_READ;
                        if ((w->events & EV_WRITE) && FD_ISSET(w->fd, &write_fds))
                            revents |= EV_WRITE;
                            
                        if (revents) {
                            // Post IO event to ESP event loop
                            io_event_data data = {
                                .watcher = w,
                                .revents = revents
                            };
                            esp_event_post_to(loop->esp_event_loop, LIBEV_EVENTS, LIBEV_IO_EVENT,
                                             &data, sizeof(data), portMAX_DELAY);
                        }
                    }
                }
                
                xSemaphoreGive(loop->io_mutex);
            }
        } else {
            // No FDs to monitor, just delay
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
    
    vTaskDelete(NULL);
}

// ESP timer callback for ev_timer
static void timer_callback(void *arg) {
    ev_timer *w = (ev_timer *)arg;
    
    if (w && w->active) {
        timer_event_data data = {
            .watcher = w,
            .revents = EV_TIMER
        };
    
        // Post timer event to ESP event loop
        esp_event_post_to(w->loop->esp_event_loop, LIBEV_EVENTS, LIBEV_TIMER_EVENT,
                         &data, sizeof(data), 0);
                         
        // Handle repeating timers
        if (w->repeat > 0) {
            // For repeating timers, restart the timer
            esp_timer_start_once(w->esp_timer_handle, 
                                (uint64_t)(w->repeat * 1000000.0));
        } else {
            // For one-shot timers, mark as inactive
            w->active = 0;
        }
    }
}

// IO event handler
static void handle_io_event(void *handler_arg, esp_event_base_t base, 
                           int32_t id, void *event_data) {
    ev_loop *loop = (ev_loop *)handler_arg;
    io_event_data *data = (io_event_data *)event_data;
    
    if (data && data->watcher && data->watcher->active && data->watcher->cb) {
        // Call the libev callback
        data->watcher->cb(loop, data->watcher, data->revents);
    }
}

// Timer event handler
static void handle_timer_event(void *handler_arg, esp_event_base_t base, 
                              int32_t id, void *event_data) {
    ev_loop *loop = (ev_loop *)handler_arg;
    timer_event_data *data = (timer_event_data *)event_data;
    
    if (data && data->watcher && data->watcher->cb) {
        // Call the libev callback
        data->watcher->cb(loop, data->watcher, data->revents);
    }
}

// Break event handler
static void handle_break_event(void *handler_arg, esp_event_base_t base, 
                              int32_t id, void *event_data) {
    ev_loop *loop = (ev_loop *)handler_arg;
    loop->running = false;
}

// Initialize a new event loop
static esp_err_t ev_loop_init(ev_loop *loop) {
    memset(loop, 0, sizeof(ev_loop));
    
    // Initialize mutex for thread safety
    loop->io_mutex = xSemaphoreCreateMutex();
    if (!loop->io_mutex) {
        ESP_LOGE(TAG, "Failed to create io_mutex");
        return ESP_FAIL;
    }
    
    // Create ESP event loop
    esp_event_loop_args_t loop_args = {
        .queue_size = 32,
        .task_name = "ev_esp_loop",
        .task_priority = 5,
        .task_stack_size = 32768,
        .task_core_id = tskNO_AFFINITY
    };
    
    esp_err_t ret = esp_event_loop_create(&loop_args, &loop->esp_event_loop);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create ESP event loop: %s", esp_err_to_name(ret));
        vSemaphoreDelete(loop->io_mutex);
        return ret;
    }
    
    // Register event handlers
    ret = esp_event_handler_register_with(loop->esp_event_loop, 
                                         LIBEV_EVENTS, LIBEV_IO_EVENT,
                                         handle_io_event, loop);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IO event handler: %s", esp_err_to_name(ret));
        esp_event_loop_delete(loop->esp_event_loop);
        vSemaphoreDelete(loop->io_mutex);
        return ret;
    }
    
    ret = esp_event_handler_register_with(loop->esp_event_loop, 
                                         LIBEV_EVENTS, LIBEV_TIMER_EVENT,
                                         handle_timer_event, loop);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register timer event handler: %s", esp_err_to_name(ret));
        esp_event_loop_delete(loop->esp_event_loop);
        vSemaphoreDelete(loop->io_mutex);
        return ret;
    }
    
    ret = esp_event_handler_register_with(loop->esp_event_loop, 
                                         LIBEV_EVENTS, LIBEV_BREAK_EVENT,
                                         handle_break_event, loop);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register break event handler: %s", esp_err_to_name(ret));
        esp_event_loop_delete(loop->esp_event_loop);
        vSemaphoreDelete(loop->io_mutex);
        return ret;
    }
    
    return ESP_OK;
}

// Initialize default event loop
void ev_default_loop_init(void) {
    ESP_ERROR_CHECK(ev_loop_init(EV_DEFAULT));
}

// Initialize an IO watcher
void ev_io_init(ev_io *watcher, void (*cb)(ev_loop *loop, ev_io *w, int revents), 
               int fd, int events) {
    memset(watcher, 0, sizeof(ev_io));
    watcher->cb = cb;
    watcher->fd = fd;
    watcher->events = events;
    watcher->active = 0;
}

// Start an IO watcher
void ev_io_start(ev_loop *loop, ev_io *watcher) {
    if (!loop) loop = EV_DEFAULT;
    
    ESP_LOGI(TAG, "Starting IO watcher for fd %d", watcher->fd);
    
    xSemaphoreTake(loop->io_mutex, portMAX_DELAY);
    
    // Find an empty slot
    int idx = -1;
    for (int i = 0; i < MAX_IO_WATCHERS; i++) {
        if (loop->io_watchers[i] == NULL) {
            idx = i;
            break;
        }
    }
    
    if (idx >= 0) {
        loop->io_watchers[idx] = watcher;
        watcher->active = 1;
        
        if (loop->io_count == 0) {
            // First IO watcher - make sure IO monitor task is running
            if (!loop->running) {
                loop->running = true;
                xTaskCreate(io_monitor_task, "io_monitor", 32768, loop, 5, &loop->io_task_handle);
            }
        }
        
        loop->io_count++;
    }
    
    xSemaphoreGive(loop->io_mutex);
}

// Stop an IO watcher
void ev_io_stop(ev_loop *loop, ev_io *watcher) {
    if (!loop) loop = EV_DEFAULT;
    
    xSemaphoreTake(loop->io_mutex, portMAX_DELAY);
    
    for (int i = 0; i < MAX_IO_WATCHERS; i++) {
        if (loop->io_watchers[i] == watcher) {
            loop->io_watchers[i] = NULL;
            watcher->active = 0;
            loop->io_count--;
            break;
        }
    }
    
    xSemaphoreGive(loop->io_mutex);
}

// Initialize a timer watcher
void ev_timer_init(ev_timer *watcher, void (*cb)(ev_loop *loop, ev_timer *w, int revents), 
                  ev_tstamp after, ev_tstamp repeat) {
    memset(watcher, 0, sizeof(ev_timer));
    watcher->cb = cb;
    watcher->repeat = repeat;
    watcher->after = after;
    watcher->active = 0;
    
    // Create ESP timer
    esp_timer_create_args_t timer_args = {
        .callback = timer_callback,
        .arg = watcher,
        .name = "ev_timer"
    };
    
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &watcher->esp_timer_handle));
}

// Start/restart a timer
void ev_timer_again(ev_loop *loop, ev_timer *watcher) {
    if (!loop) loop = EV_DEFAULT;
    
    watcher->loop = loop;
    
    // Stop timer if already running
    if (watcher->active) {
        esp_timer_stop(watcher->esp_timer_handle);
    }
    
    // Start timer
    ev_tstamp timeout = watcher->active ? watcher->repeat : watcher->after;
    ESP_LOGD(TAG, "Starting timer with timeout: %f seconds", timeout);
    esp_timer_start_once(watcher->esp_timer_handle, (uint64_t)(timeout * 1000000.0));
    watcher->active = 1;
}

// Stop a timer
void ev_timer_stop(ev_loop *loop, ev_timer *watcher) {
    if (!loop) loop = EV_DEFAULT;
    
    if (watcher->active) {
        esp_timer_stop(watcher->esp_timer_handle);
        watcher->active = 0;
    }
}

// Break the event loop
void ev_break(ev_loop *loop, int how) {
    if (!loop) loop = EV_DEFAULT;
    
    // Post break event
    esp_event_post_to(loop->esp_event_loop, LIBEV_EVENTS, LIBEV_BREAK_EVENT,
                     NULL, 0, portMAX_DELAY);
}


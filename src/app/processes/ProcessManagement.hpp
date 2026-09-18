#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

#include "Task.hpp"

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ProcessManagement {
public:
    explicit ProcessManagement(std::size_t workerCount);
    ~ProcessManagement();

    ProcessManagement(const ProcessManagement&) = delete;
    ProcessManagement& operator=(const ProcessManagement&) = delete;

    void submitToQueue(Task task);
    std::vector<TaskResult> executeTasks();

private:
    void workerLoop();
    void stopWorkers();

    std::queue<Task> taskQueue_;
    std::vector<std::thread> workers_;
    std::vector<TaskResult> results_;
    std::mutex queueMutex_;
    std::mutex resultsMutex_;
    std::condition_variable workAvailable_;
    bool stopping_ = false;
};

#endif

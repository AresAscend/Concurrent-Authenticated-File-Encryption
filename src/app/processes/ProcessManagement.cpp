#include "ProcessManagement.hpp"

#include "../encryptDecrypt/Cryption.hpp"

#include <stdexcept>

ProcessManagement::ProcessManagement(std::size_t workerCount) {
    workerCount = workerCount == 0 ? 1 : workerCount;
    workers_.reserve(workerCount);
    for (std::size_t index = 0; index < workerCount; ++index) {
        workers_.emplace_back(&ProcessManagement::workerLoop, this);
    }
}

ProcessManagement::~ProcessManagement() {
    stopWorkers();
}

void ProcessManagement::submitToQueue(Task task) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (stopping_) {
            throw std::logic_error("Cannot submit work after execution has started");
        }
        taskQueue_.push(std::move(task));
    }
    workAvailable_.notify_one();
}

std::vector<TaskResult> ProcessManagement::executeTasks() {
    stopWorkers();
    std::lock_guard<std::mutex> lock(resultsMutex_);
    return results_;
}

void ProcessManagement::workerLoop() {
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            workAvailable_.wait(lock, [this] { return stopping_ || !taskQueue_.empty(); });
            if (taskQueue_.empty()) {
                return;
            }
            task = std::move(taskQueue_.front());
            taskQueue_.pop();
        }

        TaskResult result;
        try {
            result = processFile(task);
        } catch (...) {
            result = {task.inputPath, {}, false, "Unexpected worker failure"};
        }
        std::lock_guard<std::mutex> lock(resultsMutex_);
        results_.push_back(std::move(result));
    }
}

void ProcessManagement::stopWorkers() {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        stopping_ = true;
    }
    workAvailable_.notify_all();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

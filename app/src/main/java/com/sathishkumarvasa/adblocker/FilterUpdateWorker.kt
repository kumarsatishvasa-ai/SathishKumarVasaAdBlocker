package com.sathishkumarvasa.adblocker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

class FilterUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(
    appContext,
    workerParams
) {

    override suspend fun doWork(): Result {

        val preferences =
            AppPreferences(
                applicationContext
            )

        val repository =
            FilterRepository(
                applicationContext,
                preferences
            )

        return try {

            if (!preferences.enabled.value) {
                return Result.success()
            }

            val result =
                repository.updateFilters(
                    force = false
                )

            if (result.success) {
                Result.success()
            } else {
                Result.retry()
            }

        } catch (
            _: Exception
        ) {

            Result.retry()
        }
    }

    companion object {

        const val WORK_NAME =
            "adblocker_filter_update"

        const val TAG =
            "adblocker_filter_update"
    }
}


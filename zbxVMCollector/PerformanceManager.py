#!/usr/bin/env python
from pyVmomi import vmodl, vim

perfManager = "None"

def GetPerfManDict(si, metricName):
	global perfManager
	perf_dict = {}
	content = si.RetrieveContent()
	perfManager = content.perfManager
	perfList = content.perfManager.perfCounter

	for counter in perfList:
		counter_full = "{}.{}.{}".format(counter.groupInfo.key, counter.nameInfo.key, counter.rollupType)
		perf_dict[counter_full] = counter.key
	return perf_dict[metricName]

def PerformanceMonitor(si, vm, metricName):
	perfDictID = GetPerfManDict(si, metricName)
	metricId = vim.PerformanceManager.MetricId(counterId=perfDictID, instance="")
	query = vim.PerformanceManager.QuerySpec(
										intervalId=20,
										maxSample=1,
										entity=vm,
										metricId=[metricId])
	perfResults = perfManager.QueryPerf(querySpec=[query])
	if perfResults:
		return perfResults
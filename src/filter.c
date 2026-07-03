#include "filter.h"
#include <string.h>

/**
 * 初始化筛选配置为不限制
 * @param filter 筛选配置指针
 */
void init_filter(FilterOptions *filter) {
}

/**
 * 检查数据包是否匹配筛选条件
 * @param info 数据包信息
 * @param filter 筛选配置
 * @return 匹配返回 1，不匹配返回 0
 */
int matches_filter(const PacketInfo *info, const FilterOptions *filter) {
    return 1;
}
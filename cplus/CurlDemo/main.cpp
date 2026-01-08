#include <iostream>
#include <curl/curl.h>

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    size_t total_size = size * nmemb;
    // 将返回的数据写入标准输出（控制台）
    fwrite(ptr, size, nmemb, (FILE *)stream);
    return total_size;
}
// TIP 要<b>Run</b>代码，请按 <shortcut actionId="Run"/> 或点击装订区域中的 <icon src="AllIcons.Actions.Execute"/> 图标。
int main() {
    CURL *curl;          // curl 核心句柄
    CURLcode res;        // 请求结果状态码

    // 初始化 curl 环境
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // 创建 curl 句柄
    curl = curl_easy_init();
    if(curl) {
        // 设置要请求的 URL（示例：请求百度首页）
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.baidu.com");

        // 设置 SSL 验证（新手可先关闭，避免证书问题）
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // 设置数据接收的回调函数
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);

        // 执行 HTTP 请求
        res = curl_easy_perform(curl);

        // 检查请求是否成功
        if(res != CURLE_OK) {
            fprintf(stderr, "curl 请求失败: %s\n", curl_easy_strerror(res));
        }

        // 释放 curl 句柄
        curl_easy_cleanup(curl);
    }

    // 清理 curl 全局环境
    curl_global_cleanup();

    return 0;
    // TIP 请访问 <a href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a> 查看 CLion 帮助。此外，您还可以从主菜单中选择“帮助 | 学习 IDE 功能”，尝试 CLion 的交互式课次。
}
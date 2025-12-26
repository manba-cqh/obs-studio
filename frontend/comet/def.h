#pragma once

// 窗口大小调整相关
enum ResizeEdge {
    EdgeNone = 0,
    EdgeTop = 1,
    EdgeBottom = 2,
    EdgeLeft = 4,
    EdgeRight = 8,
    EdgeTopLeft = EdgeTop | EdgeLeft,
    EdgeTopRight = EdgeTop | EdgeRight,
    EdgeBottomLeft = EdgeBottom | EdgeLeft,
    EdgeBottomRight = EdgeBottom | EdgeRight
};

// 边缘检测区域大小
#define RESIZE_MARGIN 5
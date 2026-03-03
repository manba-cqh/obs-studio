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

// dock 与中央区域间分隔条检测区：在此边缘范围内拦截鼠标，禁止拖动
#define DOCK_SEPARATOR_BLOCK_MARGIN 10
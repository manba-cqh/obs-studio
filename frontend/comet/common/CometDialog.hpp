#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QWidget>
#include "DialogTitleBar.hpp"

/**
 * 通用圆角无边框对话框基类
 * - 无边框、透明背景、圆角样式、setMask
 * - 内置 DialogTitleBar 和内容区域
 * - 子类通过 contentWidget() 添加内容，或使用 finishCometLayout() 迁移 ui->setupUi 的内容
 */
class CometDialog : public QDialog
{
	Q_OBJECT

public:
	/** @param deferLayout 为 true 时延后设置布局，供子类先调用 ui->setupUi 再调用 finishCometLayout() 迁移内容 */
	explicit CometDialog(const QString &title, QWidget *parent = nullptr,
	                    DialogTitleBar::CornerStyle cornerStyle = DialogTitleBar::CornerStyle::TopRounded,
	                    bool deferLayout = false);
	~CometDialog();

	/** 标题栏 */
	DialogTitleBar *titleBar() const { return m_titleBar; }
	/** 内容区域，子类在此添加控件 */
	QWidget *contentWidget() const { return m_contentWidget; }
	/** 容器（标题栏+内容区的父级） */
	QWidget *containerWidget() const { return m_container; }

	/** 设置对话框尺寸 */
	void setDialogSize(int w, int h);
	/** 设置背景色 */
	void setBackgroundColor(const QColor &color);
	/** 设置圆角半径 */
	void setCornerRadius(int radius);
	/** 设置内容区内边距 */
	void setContentMargins(int left, int top, int right, int bottom);
	/** 更新圆角 mask */
	void updateMask();

	/** 迁移当前 layout 的内容到 contentWidget，并设置容器布局（deferLayout=true 时在 ui->setupUi 之后调用） */
	void finishCometLayout();
	/** 仅设置容器为对话框布局（子类自定义迁移后调用） */
	void setCometLayout();

protected:
	void paintEvent(QPaintEvent *event) override;
	void resizeEvent(QResizeEvent *event) override;

	QWidget *m_container;
	QWidget *m_contentWidget;
	DialogTitleBar *m_titleBar;
	QColor m_backgroundColor;
	int m_cornerRadius;
	QMargins m_contentMargins;
	bool m_deferLayout;
};

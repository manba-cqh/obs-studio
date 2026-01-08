#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QWidget>
#include <QMap>
#include <QSet>
#include "MovableWidget.hpp"

struct SourceTypeInfo {
	QString id;
	QString name;
	QString iconPath;
};

class SourceToolDialog : public QDialog
{
	Q_OBJECT
signals:
	void sourceTypeSelected(const QString &sourceId);
	void sourceTypeRemoved(const QString &sourceId);

public:
	SourceToolDialog(QWidget *parent = nullptr);
	~SourceToolDialog();

protected:
	void paintEvent(QPaintEvent *event) override;

private:
	void initUI();
	void setupCategories();
	QWidget* createCategorySection(const QString &title, const QList<SourceTypeInfo> &sources);
	QPushButton* createSourceButton(const SourceTypeInfo &info, bool isCommon = false);
	
	void addToCommon(const QString &sourceId);
	void removeFromCommon(const QString &sourceId);
	void updateCommonSection();
	void saveCommonSources();
	void loadCommonSources();

private:
	QVBoxLayout *m_mainLayout;
	QWidget *m_contentWidget;
	QPushButton *m_closeBtn;
	
	// 常用工具区域
	QWidget *m_commonSection;
	QGridLayout *m_commonGrid;
	
	// 所有源类型
	QMap<QString, SourceTypeInfo> m_allSources;
	// 常用源ID列表
	QStringList m_commonSourceIds;
	
	// 类别和对应的源
	QList<QPair<QString, QList<SourceTypeInfo>>> m_categories;
};


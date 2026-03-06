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
#include "common/CometDialog.hpp"

struct SourceTypeInfo {
	QString id;
	QString name;
	QString iconPath;
};

class SourceToolDialog : public CometDialog
{
	Q_OBJECT
signals:
	void sourceTypeSelected(const QString &sourceId);
	void sourceTypeRemoved(const QString &sourceId);

public:
	SourceToolDialog(QWidget *parent = nullptr);
	~SourceToolDialog();

private:
	void initUI();
	void setupCategories();
	/** 从指定行起填充常用按钮和所有分类（同一网格，列对齐）；返回下一空行 */
	int addCommonAndCategoryRows(int startRow);
	QPushButton* createSourceButton(const SourceTypeInfo &info, bool isCommon = false);
	
	void addToCommon(const QString &sourceId);
	void removeFromCommon(const QString &sourceId);
	void updateCommonSection();
	void saveCommonSources();
	void loadCommonSources();

private:
	static const int GRID_COLS = 5;
	QGridLayout *m_contentGrid;
	/** 内容网格行数（用于 updateCommonSection 时清除重填） */
	int m_contentGridRows;
	
	// 所有源类型
	QMap<QString, SourceTypeInfo> m_allSources;
	// 常用源ID列表
	QStringList m_commonSourceIds;
	
	// 类别和对应的源
	QList<QPair<QString, QList<SourceTypeInfo>>> m_categories;
};


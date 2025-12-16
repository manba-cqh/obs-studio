#pragma once

#include "common/PanelContainer.hpp"
#include <QGridLayout>
#include <QListWidget>
#include <QPushButton>
#include <QButtonGroup>

class ScenePanel : public PanelContainer
{
	Q_OBJECT

public:
	ScenePanel(QWidget *parent = nullptr);
	~ScenePanel();

private slots:
    void onBroadcastButtonClicked();
    void onAddSceneButtonClicked();
    void onAddSourceButtonClicked();
    void onSceneButtonClicked(int id);
    void onClearSourceButtonClicked();

private:
    void initUI();
    void createHeaderOperWidget();
    void createContentWidget();
    void setupSceneButtons();
    void addSceneButton(const QString &name, int row, int col);
    void selectScene(int index);
    QString getChineseNumber(int number);

private:
    QPushButton *m_broadcastButton;

    QGridLayout *m_sceneGridLayout;
    QButtonGroup *m_sceneButtonGroup;
    QPushButton *m_addSceneButton;
    QListWidget *m_currentContentList;
    QPushButton *m_addSourceButton;
    QPushButton *m_clearSourceButton;
    
    int m_currentSceneIndex;
    QList<QPushButton*> m_sceneButtons;
};


#pragma once

#include "PanelContainer.hpp"
#include <QGridLayout>
#include <QListWidget>
#include <QPushButton>
#include <QButtonGroup>
#include <QList>
#include <obs.hpp>
#include <obs-frontend-api.h>

class SceneListItemWidget;
class DirectorWidget;

class ScenePanel : public PanelContainer
{
	Q_OBJECT
signals:
	void sourcesChanged();
	void broadcastModeToggled(bool enabled);

public:
	ScenePanel(QWidget *parent = nullptr);
	~ScenePanel();

	QPushButton *getBroadcastButton() const { return m_broadcastButton; }
	
	void updateCurrentSceneSources();
	void syncSourceSelectionFromPreview();

public slots:
	void refreshSceneList();
    void onBroadcastButtonClicked();
    void onAddSceneButtonClicked();
    void onAddSourceButtonClicked();
    void onSceneItemClicked(OBSSource source);
    void onClearSourceButtonClicked();
	void onSceneChanged();

private:
    void initUI();
    void createHeaderOperWidget();
    void createContentWidget();
    void setupSceneButtons();
    void addSceneItem(OBSSource source, int row, int col);
    void selectScene(int index);
    static void OBSFrontendEvent(enum obs_frontend_event event, void *ptr);

private:
    QPushButton *m_broadcastButton;

    QGridLayout *m_sceneGridLayout;
    QPushButton *m_addSceneButton;
    QListWidget *m_currentContentList;
    QPushButton *m_addSourceButton;
    QPushButton *m_clearSourceButton;
    
    int m_currentSceneIndex;
    QList<SceneListItemWidget*> m_sceneItems;
};


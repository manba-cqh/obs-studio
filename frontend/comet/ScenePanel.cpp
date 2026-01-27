#include "ScenePanel.hpp"
#include <QGridLayout>
#include <QButtonGroup>
#include <QFontMetrics>
#include <QCursor>
#include <QSpacerItem>

#include "tools/tools.hpp"
#include "SourceToolDialog.hpp"
#include <obs-frontend-api.h>
#include <obs.hpp>
#include <widgets/OBSBasic.hpp>
#include "SourceListItemWidget.hpp"
#include "SceneListItemWidget.hpp"
#include <dialogs/NameDialog.hpp>
#include <qt-wrappers.hpp>
#include <string>
#include "DirectorWidget.hpp"

#include <vector>

using std::vector;

namespace {

// 枚举场景中的所有 scene item，用于批量删除
static bool CollectSceneItems(obs_scene_t *, obs_sceneitem_t *item, void *param)
{
	auto *items = static_cast<vector<OBSSceneItem> *>(param);
	items->emplace_back(item);
	return true;
}

} // namespace

ScenePanel::ScenePanel(QWidget *parent)
	: PanelContainer(parent)
	, m_currentSceneIndex(0)
{
	initUI();
	
	// 注册 OBS 前端事件回调，监听场景列表变化
	obs_frontend_add_event_callback(OBSFrontendEvent, this);
}

ScenePanel::~ScenePanel()
{
	// 移除事件回调
	obs_frontend_remove_event_callback(OBSFrontendEvent, this);
	
	// 清理场景项列表
	m_sceneItems.clear();
}

void ScenePanel::initUI()
{
   createHeaderOperWidget();
   createContentWidget();
}

void ScenePanel::createHeaderOperWidget()
{
    m_broadcastButton = new QPushButton(this);
    m_broadcastButton->setFixedSize(56, 24);
    m_broadcastButton->setCheckable(true);
    m_broadcastButton->setChecked(false);
    m_broadcastButton->setStyleSheet(QString("QPushButton { border-image: url(:/images/director.svg); }" \
        "QPushButton:hover { border-image: url(:/images/director_hover.svg); }" \
        "QPushButton:checked { border-image: url(:/images/director_hover.svg); }") \
    );
    connect(m_broadcastButton, &QPushButton::clicked, this, &ScenePanel::onBroadcastButtonClicked);
}

void ScenePanel::createContentWidget()
{
    QWidget *contentWidget = new QWidget(this);
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(5);

    // 创建场景列表区域
    QWidget *sceneListWidget = new QWidget(contentWidget);
    m_sceneGridLayout = new QGridLayout(sceneListWidget);
    m_sceneGridLayout->setContentsMargins(0, 0, 0, 0);
    m_sceneGridLayout->setSpacing(5);

    m_addSceneButton = new QPushButton(this);
    m_addSceneButton->setFixedSize(24, 24);
    m_addSceneButton->setStyleSheet(BUTTON_QSS_STYLE("add.svg", "add_hover.svg", "add_hover.svg"));
    connect(m_addSceneButton, &QPushButton::clicked, this, &ScenePanel::onAddSceneButtonClicked);
    contentLayout->addWidget(sceneListWidget);

    QWidget *separator = new QWidget(contentWidget);
    separator->setFixedHeight(1);
    separator->setStyleSheet("QWidget { background-color: rgba(255, 255, 255, 125); }");
    contentLayout->addWidget(separator);

    // 创建内容列表区域
    QWidget *listWidgetContainer = new QWidget(contentWidget);
    QVBoxLayout *listLayout = new QVBoxLayout(listWidgetContainer);
    listLayout->setContentsMargins(0, 0, 0, 0);
    listLayout->setSpacing(0);

    m_currentContentList = new QListWidget(listWidgetContainer);
    m_currentContentList->setSpacing(2);
    listLayout->addWidget(m_currentContentList);
    contentLayout->addWidget(listWidgetContainer);

    setupSceneButtons();

    // 创建底部"添加直播素材"按钮
    QWidget *addSourceButtonContainer = new QWidget(contentWidget);
    addSourceButtonContainer->setFixedHeight(30);
    addSourceButtonContainer->setStyleSheet("background: rgba(21, 21, 32, 1);");
    QHBoxLayout *addSourceButtonLayout = new QHBoxLayout(addSourceButtonContainer);
    addSourceButtonLayout->setContentsMargins(10, 0, 10, 0);
    addSourceButtonLayout->setSpacing(0);
    m_addSourceButton = new QPushButton("添加直播素材", contentWidget);
    m_addSourceButton->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(14));
    m_addSourceButton->setFixedSize(120, 24);
    m_addSourceButton->setIcon(QIcon(":/images/add.svg"));
    connect(m_addSourceButton, &QPushButton::clicked, this, &ScenePanel::onAddSourceButtonClicked);
    addSourceButtonLayout->addWidget(m_addSourceButton);
    addSourceButtonLayout->addStretch();
    m_clearSourceButton = new QPushButton("清空", contentWidget);
    m_clearSourceButton->setStyleSheet(BUTTON_TRANSPARENT_QSS_STYLE(14));
    m_clearSourceButton->setFixedSize(42, 24);
    connect(m_clearSourceButton, &QPushButton::clicked, this, &ScenePanel::onClearSourceButtonClicked);
    addSourceButtonLayout->addWidget(m_clearSourceButton);
    contentLayout->addWidget(addSourceButtonContainer);

    setContentWidget(contentWidget);
}

void ScenePanel::setupSceneButtons()
{
	// 清空现有场景项
	for (auto *item : m_sceneItems) {
		m_sceneGridLayout->removeWidget(item);
		delete item;
	}
	m_sceneItems.clear();

	// 从 OBS 获取场景列表
	struct obs_frontend_source_list scenes = {0};
	obs_frontend_get_scenes(&scenes);

	// 为每个场景创建项
	// 注意：不要手动调用 obs_source_release，应该由 obs_frontend_source_list_free 统一管理
	int sceneCount = (int)scenes.sources.num;
	for (int i = 0; i < sceneCount; i++) {
		obs_source_t *source = scenes.sources.array[i];
		
		int row = i / 3;
		int col = i % 3;
		addSceneItem(source, row, col);
	}

	// 释放场景列表
	obs_frontend_source_list_free(&scenes);

	// 更新"+"按钮位置
	if (m_addSceneButton) {
		m_sceneGridLayout->removeWidget(m_addSceneButton);
		int totalItems = m_sceneItems.size();
		int nextRow = totalItems / 3;
		int nextCol = totalItems % 3;
		m_sceneGridLayout->addWidget(m_addSceneButton, nextRow, nextCol);
	}
	
	// 为每行添加弹簧：如果行中少于3个item，在剩余位置添加弹簧
	int totalItems = m_sceneItems.size() + (m_addSceneButton ? 1 : 0);
	int totalRows = (totalItems + 2) / 3; // 向上取整
	
	// 先清理可能存在的旧弹簧（遍历所有可能存在的行）
	for (int row = 0; row < totalRows + 1; row++) { // 多遍历一行以确保清理干净
		for (int col = 0; col < 3; col++) {
			QLayoutItem *item = m_sceneGridLayout->itemAtPosition(row, col);
			if (item && item->spacerItem()) {
				m_sceneGridLayout->removeItem(item);
				delete item;
			}
		}
	}
	
	// 为每行添加弹簧
	for (int row = 0; row < totalRows; row++) {
		int itemsInRow = 0;
		// 计算当前行的item数量（包括场景项和"+"按钮）
		for (int col = 0; col < 3; col++) {
			QLayoutItem *item = m_sceneGridLayout->itemAtPosition(row, col);
			if (item && item->widget()) {
				itemsInRow++;
			}
		}
		
		// 如果当前行少于3个item，在剩余位置添加弹簧
		if (itemsInRow < 3) {
			// 在剩余的空位置添加弹簧
			for (int col = 0; col < 3; col++) {
				QLayoutItem *item = m_sceneGridLayout->itemAtPosition(row, col);
				if (!item) {
					// 该位置为空，添加弹簧
					QSpacerItem *spacer = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);
					m_sceneGridLayout->addItem(spacer, row, col);
				}
			}
		}
	}

	// 选择第一个场景
	if (!m_sceneItems.isEmpty()) {
		selectScene(0);
	}
}

void ScenePanel::addSceneItem(OBSSource source, int row, int col)
{
	if (!source) {
		return;
	}

	SceneListItemWidget *sceneItem = new SceneListItemWidget(source, this);
	sceneItem->setFixedHeight(34);
    sceneItem->setMaximumWidth(82);
	
	// 连接信号
	connect(sceneItem, &SceneListItemWidget::sceneSelected, this, &ScenePanel::onSceneItemClicked);
	connect(sceneItem, &SceneListItemWidget::sceneChanged, this, &ScenePanel::onSceneChanged);
	
	m_sceneItems.append(sceneItem);
	m_sceneGridLayout->addWidget(sceneItem, row, col);
}

void ScenePanel::selectScene(int index)
{
	for (SceneListItemWidget *item : m_sceneItems) {
		item->setChecked(false);
	}
	if (index >= 0 && index < m_sceneItems.size()) {
		m_currentSceneIndex = index;
		m_sceneItems[index]->setChecked(true);
	}
}

void ScenePanel::onBroadcastButtonClicked()
{
	// 发送信号通知主窗口切换导播模式
	bool checked = m_broadcastButton->isChecked();
	emit broadcastModeToggled(checked);
}

void ScenePanel::onAddSceneButtonClicked()
{
    OBSBasic *main = OBSBasic::Get();
    if (!main) {
        return;
    }
    
    // 生成默认场景名称
    std::string name;
    QString format{QTStr("Basic.Main.DefaultSceneName.Text")};
    
    int i = 2;
    QString placeHolderText = format.arg(i);
    OBSSourceAutoRelease source = nullptr;
    while ((source = obs_get_source_by_name(QT_TO_UTF8(placeHolderText)))) {
        placeHolderText = format.arg(++i);
    }
    
    // 显示名称输入对话框
    bool accepted = NameDialog::AskForName(this, QTStr("Basic.Main.AddSceneDlg.Title"),
                                           QTStr("Basic.Main.AddSceneDlg.Text"), name, placeHolderText);
    
    if (accepted) {
        if (name.empty()) {
            QMessageBox::warning(this, QTStr("NoNameEntered.Title"), QTStr("NoNameEntered.Text"));
            return;
        }
        
        // 检查名称是否已存在
        OBSSourceAutoRelease existing = obs_get_source_by_name(name.c_str());
        if (existing) {
            QMessageBox::warning(this, QTStr("NameExists.Title"), QTStr("NameExists.Text"));
            return;
        }
        
        // 创建场景
        OBSSceneAutoRelease scene = obs_scene_create(name.c_str());
        if (scene) {
            obs_source_t *scene_source = obs_scene_get_source(scene);
            
			// 添加新场景项到 UI
			int totalItems = m_sceneItems.size();
			int row = totalItems / 3;
			int col = totalItems % 3;
			addSceneItem(scene_source, row, col);
	
			// 移动"+"按钮到下一个位置
			m_sceneGridLayout->removeWidget(m_addSceneButton);
			int nextRow = (totalItems + 1) / 3;
			int nextCol = (totalItems + 1) % 3;
			m_sceneGridLayout->addWidget(m_addSceneButton, nextRow, nextCol);
			
			// 设置当前场景，这会触发 AddScene 回调并更新 OBS 的内部状态
			main->SetCurrentScene(scene_source);
	
			// 选中新添加的场景
			selectScene(totalItems);
        }
    }
}

void ScenePanel::onAddSourceButtonClicked()
{
    SourceToolDialog *dialog = new SourceToolDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    
    connect(dialog, &SourceToolDialog::sourceTypeSelected, this, [this](const QString &sourceId) {
        OBSBasic *main = OBSBasic::Get();
        if (main) {
            // 使用 OBS 添加指定类型的源
            main->AddSource(sourceId.toUtf8().constData());

            emit sourcesChanged();
            
            // 刷新列表
            updateCurrentSceneSources();
        }
    });
    
    // 居中显示对话框
    QWidget *mainWindow = window();
    if (mainWindow) {
        QPoint center = mainWindow->geometry().center();
        dialog->move(center.x() - dialog->width() / 2, center.y() - dialog->height() / 2);
    }
    
    dialog->show();
}

void ScenePanel::onSceneItemClicked(OBSSource source)
{
	if (!source) {
		return;
	}
	
	// 找到对应的场景项索引
	int index = -1;
	for (int i = 0; i < m_sceneItems.size(); i++) {
		if (m_sceneItems[i] && m_sceneItems[i]->text() == QString::fromUtf8(obs_source_get_name(source))) {
			index = i;
			break;
		}
	}
	
	if (index >= 0) {
		selectScene(index);
	}
	
	// 切换到对应的场景
	obs_frontend_set_current_scene(source);
	
	// 更新当前场景的源列表
	updateCurrentSceneSources();
}

void ScenePanel::onSceneChanged()
{
	// 刷新场景列表
	refreshSceneList();
}

void ScenePanel::refreshSceneList()
{
	setupSceneButtons();
	
	// 恢复当前选中的场景
	struct obs_frontend_source_list scenes = {0};
	obs_frontend_get_scenes(&scenes);
	
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		OBSScene currentScene = main->GetCurrentScene();
		if (currentScene) {
			OBSSource currentSource = obs_scene_get_source(currentScene);
			if (currentSource) {
				const char *currentName = obs_source_get_name(currentSource);
				for (int i = 0; i < m_sceneItems.size(); i++) {
					if (m_sceneItems[i] && m_sceneItems[i]->text() == QString::fromUtf8(currentName)) {
						selectScene(i);
						break;
					}
				}
			}
		}
	}
	
	obs_frontend_source_list_free(&scenes);
}

void ScenePanel::onClearSourceButtonClicked()
{
    // 弹窗确认
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认清空", "确定要清空当前场景中的所有直播素材吗？",
                                  QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) {
        return;
    }
    // 清空当前场景中的所有源
    OBSBasic *main = OBSBasic::Get();
    if (!main) {
        return;
    }

    OBSScene scene = main->GetCurrentScene();
    if (!scene) {
        return;
    }

    vector<OBSSceneItem> items;
    obs_scene_enum_items(scene, CollectSceneItems, &items);

    // 如果没有源，直接返回
    if (items.empty()) {
        return;
    }

    // 依次从场景中移除所有 scene item
    for (auto &item : items) {
        obs_sceneitem_remove(item);
    }

    // 更新列表 UI
    updateCurrentSceneSources();
    
    // 通知预览窗口刷新
    emit sourcesChanged();
}

void ScenePanel::updateCurrentSceneSources()
{
    if (!m_currentContentList) {
        return;
    }
    
    // 清空列表
    m_currentContentList->clear();
    
    // 获取当前场景
    OBSBasic *main = OBSBasic::Get();
    if (!main) {
        return;
    }
    
    OBSScene scene = main->GetCurrentScene();
    if (!scene) {
        return;
    }
    
    // 枚举场景中的所有项
    struct EnumData {
        QListWidget *list;
        ScenePanel *panel;
    };
    
    EnumData enumData;
    enumData.list = m_currentContentList;
    enumData.panel = this;
    
    auto enumItem = [](obs_scene_t *, obs_sceneitem_t *item, void *param) -> bool {
        EnumData *data = static_cast<EnumData *>(param);
        QListWidget *list = data->list;
        ScenePanel *panel = data->panel;
        
        obs_source_t *source = obs_sceneitem_get_source(item);
        if (!source || obs_source_removed(source)) {
            return true;
        }
        
        const char *sourceName = obs_source_get_name(source);
        if (sourceName) {
            // 获取 source ID
            const char *sourceId = obs_source_get_id(source);
            
            // 创建空的 QListWidgetItem，将文本交给自定义控件处理
            QListWidgetItem *listItem = new QListWidgetItem(list);

            // 创建自定义 item 控件，传递 sceneitem 和 source ID
            auto *itemWidget = new SourceListItemWidget(QString::fromUtf8(sourceName), item, sourceId, list);
            connect(itemWidget, &SourceListItemWidget::sourcesChanged, panel, [panel]() {
                panel->updateCurrentSceneSources();
                emit panel->sourcesChanged();
            });

            // 使用控件的 sizeHint 作为行高，避免上下重叠
            listItem->setSizeHint(itemWidget->sizeHint());
            list->setItemWidget(listItem, itemWidget);
        }
        
        return true;
    };
    
    obs_scene_enum_items(scene, enumItem, &enumData);
}

void ScenePanel::OBSFrontendEvent(enum obs_frontend_event event, void *ptr)
{
	ScenePanel *panel = static_cast<ScenePanel *>(ptr);
	if (!panel) {
		return;
	}
	
	switch (event) {
	case OBS_FRONTEND_EVENT_SCENE_LIST_CHANGED:
		// 场景列表变化时刷新
		QMetaObject::invokeMethod(panel, "refreshSceneList", Qt::QueuedConnection);
		break;
	case OBS_FRONTEND_EVENT_SCENE_CHANGED:
		// 场景切换时更新选中状态
		QMetaObject::invokeMethod(panel, "refreshSceneList", Qt::QueuedConnection);
		break;
	default:
		break;
	}
}
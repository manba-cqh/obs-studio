#include "OBSBasicAdvAudio.hpp"
#include "ui_OBSAdvAudio.h"

#include <components/OBSAdvAudioCtrl.hpp>
#include <utility/item-widget-helpers.hpp>
#include <widgets/OBSBasic.hpp>

#include <QPushButton>
#include <QFile>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QWidget>
#include "comet/common/MovableWidget.hpp"
#include <QPainter>
#include <QStyleOption>
#include <QPainterPath>
#include <qt-wrappers.hpp>

#include "moc_OBSBasicAdvAudio.cpp"

OBSBasicAdvAudio::OBSBasicAdvAudio(QWidget *parent) : QDialog(parent), ui(new Ui::OBSAdvAudio), showInactive(false)
{
	// 设置窗口为无边框，以便使用 MovableWidget
	setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
	setAttribute(Qt::WA_TranslucentBackground, false);
	setAutoFillBackground(true);
	setObjectName("OBSBasicAdvAudio");
	
	// 加载 OBSBasicAdvAudio 专用样式文件（使用与 OBSBasicProperties 相同的样式）
	QFile styleFile(":/property_styles.qss");
	if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
		QString style = QString::fromUtf8(styleFile.readAll());
		// 将 OBSBasicProperties 替换为 OBSBasicAdvAudio
		style.replace("OBSBasicProperties", "OBSBasicAdvAudio");
		setStyleSheet(style);
		styleFile.close();
	}
	
	// 创建容器 widget
	QWidget *container = new QWidget(this);
	container->setStyleSheet("QWidget { background-color: #1F1F2C; border-radius: 0px; }");
	
	QVBoxLayout *containerLayout = new QVBoxLayout(container);
	containerLayout->setContentsMargins(0, 0, 0, 0);
	containerLayout->setSpacing(0);

	// 创建标题栏
	MovableWidget *titleBar = new MovableWidget(this, container);
	titleBar->setStyleSheet("MovableWidget { background-color: #2C2C3C; }");
	titleBar->setFixedHeight(50);
	QHBoxLayout *titleLayout = new QHBoxLayout(titleBar);
	titleLayout->setContentsMargins(15, 13, 15, 13);
	titleLayout->setSpacing(0);
	
	// 标题标签
	QLabel *titleLabel = new QLabel(titleBar);
	titleLabel->setTextFormat(Qt::PlainText);
	titleLabel->setText(QTStr("Basic.AdvAudio"));
	titleLabel->setStyleSheet("QLabel { color: #FFFFFF; font-size: 15px; font-weight: bold; background: transparent; border: none; padding: 0px; }");
	titleLayout->addWidget(titleLabel, 0, Qt::AlignVCenter);
	titleLayout->addStretch();
	
	// 关闭按钮
	QPushButton *closeBtn = new QPushButton(titleBar);
	closeBtn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
	closeBtn->setFixedSize(24, 24);
	closeBtn->setCursor(Qt::PointingHandCursor);
	closeBtn->setStyleSheet(
		"QPushButton {"
		"    border: none;"
		"    background: transparent;"
		"    padding: 0px;"
		"    margin: 0px;"
		"    border-image: url(:/images/close.svg);"
		"}"
		"QPushButton:hover {"
		"    border-image: url(:/images/close_hover.svg);"
		"}"
		"QPushButton:pressed {"
		"    border-image: url(:/images/close_pressed.svg);"
		"}"
	);
	connect(closeBtn, &QPushButton::clicked, this, &QDialog::close);
	titleLayout->addWidget(closeBtn, 0, Qt::AlignVCenter | Qt::AlignRight);
	containerLayout->addWidget(titleBar);

	// 设置 UI（这会创建原有的布局）
	ui->setupUi(this);
	
	// 获取原有的布局和内容
	QGridLayout *originalLayout = qobject_cast<QGridLayout *>(this->layout());
	if (originalLayout) {
		// 创建内容布局
		QVBoxLayout *contentLayout = new QVBoxLayout();
		contentLayout->setContentsMargins(15, 15, 15, 15);
		contentLayout->setSpacing(15);
		
		// 移除所有项目并添加到容器中
		// QGridLayout 需要按行和列遍历
		for (int row = 0; row < originalLayout->rowCount(); ++row) {
			for (int col = 0; col < originalLayout->columnCount(); ++col) {
				QLayoutItem *item = originalLayout->itemAtPosition(row, col);
				if (item) {
					if (item->widget()) {
						contentLayout->addWidget(item->widget());
					} else if (item->layout()) {
						contentLayout->addLayout(item->layout());
					}
				}
			}
		}
		
		// 清理原始布局
		QLayoutItem *item;
		while ((item = originalLayout->takeAt(0)) != nullptr) {
			delete item;
		}
		delete originalLayout;
		
		containerLayout->addLayout(contentLayout);
	}

	// 设置对话框布局
	QVBoxLayout *dialogLayout = new QVBoxLayout(this);
	dialogLayout->setContentsMargins(0, 0, 0, 0);
	dialogLayout->addWidget(container);

	signal_handler_t *sh = obs_get_signal_handler();
	sigs.emplace_back(sh, "source_audio_activate", OBSSourceAdded, this);
	sigs.emplace_back(sh, "source_audio_deactivate", OBSSourceRemoved, this);
	sigs.emplace_back(sh, "source_activate", OBSSourceActivated, this);
	sigs.emplace_back(sh, "source_deactivate", OBSSourceRemoved, this);

	VolumeType volType = (VolumeType)config_get_int(App()->GetUserConfig(), "BasicWindow", "AdvAudioVolumeType");

	if (volType == VolumeType::Percent)
		ui->usePercent->setChecked(true);

	installEventFilter(CreateShortcutFilter());

	/* enum user scene/sources */
	obs_enum_sources(EnumSources, this);

	setAttribute(Qt::WA_DeleteOnClose, true);
}

OBSBasicAdvAudio::~OBSBasicAdvAudio()
{
	OBSBasic *main = OBSBasic::Get();

	for (size_t i = 0; i < controls.size(); ++i)
		delete controls[i];

	main->SaveProject();
}

bool OBSBasicAdvAudio::EnumSources(void *param, obs_source_t *source)
{
	OBSBasicAdvAudio *dialog = static_cast<OBSBasicAdvAudio *>(param);
	uint32_t flags = obs_source_get_output_flags(source);

	if ((flags & OBS_SOURCE_AUDIO) != 0 &&
	    (dialog->showInactive || (obs_source_active(source) && obs_source_audio_active(source))))
		dialog->AddAudioSource(source);

	return true;
}

void OBSBasicAdvAudio::OBSSourceAdded(void *param, calldata_t *calldata)
{
	OBSSource source((obs_source_t *)calldata_ptr(calldata, "source"));

	QMetaObject::invokeMethod(static_cast<OBSBasicAdvAudio *>(param), "SourceAdded", Q_ARG(OBSSource, source));
}

void OBSBasicAdvAudio::OBSSourceRemoved(void *param, calldata_t *calldata)
{
	OBSSource source((obs_source_t *)calldata_ptr(calldata, "source"));

	QMetaObject::invokeMethod(static_cast<OBSBasicAdvAudio *>(param), "SourceRemoved", Q_ARG(OBSSource, source));
}

void OBSBasicAdvAudio::OBSSourceActivated(void *param, calldata_t *calldata)
{
	OBSSource source((obs_source_t *)calldata_ptr(calldata, "source"));

	if (obs_source_audio_active(source))
		QMetaObject::invokeMethod(static_cast<OBSBasicAdvAudio *>(param), "SourceAdded",
					  Q_ARG(OBSSource, source));
}

inline void OBSBasicAdvAudio::AddAudioSource(obs_source_t *source)
{
	for (size_t i = 0; i < controls.size(); i++) {
		if (controls[i]->GetSource() == source)
			return;
	}
	OBSAdvAudioCtrl *control = new OBSAdvAudioCtrl(ui->mainLayout, source);

	InsertQObjectByName(controls, control);

	for (auto control : controls) {
		control->ShowAudioControl(ui->mainLayout);
	}
}

void OBSBasicAdvAudio::SourceAdded(OBSSource source)
{
	uint32_t flags = obs_source_get_output_flags(source);

	if ((flags & OBS_SOURCE_AUDIO) == 0)
		return;

	AddAudioSource(source);
}

void OBSBasicAdvAudio::SourceRemoved(OBSSource source)
{
	uint32_t flags = obs_source_get_output_flags(source);

	if ((flags & OBS_SOURCE_AUDIO) == 0)
		return;

	for (size_t i = 0; i < controls.size(); i++) {
		if (controls[i]->GetSource() == source) {
			delete controls[i];
			controls.erase(controls.begin() + i);
			break;
		}
	}
}

void OBSBasicAdvAudio::on_usePercent_toggled(bool checked)
{
	VolumeType type;

	if (checked)
		type = VolumeType::Percent;
	else
		type = VolumeType::dB;

	for (size_t i = 0; i < controls.size(); i++)
		controls[i]->SetVolumeWidget(type);

	config_set_int(App()->GetUserConfig(), "BasicWindow", "AdvAudioVolumeType", (int)type);
}

void OBSBasicAdvAudio::on_activeOnly_toggled(bool checked)
{
	SetShowInactive(!checked);
}

void OBSBasicAdvAudio::SetShowInactive(bool show)
{
	if (showInactive == show)
		return;

	showInactive = show;

	sigs.clear();
	signal_handler_t *sh = obs_get_signal_handler();

	if (showInactive) {
		sigs.emplace_back(sh, "source_create", OBSSourceAdded, this);
		sigs.emplace_back(sh, "source_remove", OBSSourceRemoved, this);

		obs_enum_sources(EnumSources, this);

		SetIconsVisible(showVisible);
	} else {
		sigs.emplace_back(sh, "source_audio_activate", OBSSourceAdded, this);
		sigs.emplace_back(sh, "source_audio_deactivate", OBSSourceRemoved, this);
		sigs.emplace_back(sh, "source_activate", OBSSourceActivated, this);
		sigs.emplace_back(sh, "source_deactivate", OBSSourceRemoved, this);

		for (size_t i = 0; i < controls.size(); i++) {
			const auto source = controls[i]->GetSource();
			if (!(obs_source_active(source) && obs_source_audio_active(source))) {
				delete controls[i];
				controls.erase(controls.begin() + i);
				i--;
			}
		}
	}
}

void OBSBasicAdvAudio::SetIconsVisible(bool visible)
{
	showVisible = visible;

	QLayoutItem *item = ui->mainLayout->itemAtPosition(0, 0);
	QLabel *headerLabel = qobject_cast<QLabel *>(item->widget());
	visible ? headerLabel->show() : headerLabel->hide();

	for (size_t i = 0; i < controls.size(); i++) {
		controls[i]->SetIconVisible(visible);
	}
}

void OBSBasicAdvAudio::paintEvent(QPaintEvent *event)
{
	QStyleOption opt;
	opt.initFrom(this);
	QPainter p(this);
	style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
	QDialog::paintEvent(event);
}

/**
 * @file cutter-plugin/R2RetDec.cpp
 * @brief Decompiler wrapper to be used to register with Cutter.
 *
 * This file is based on cutter-plugin/R2GhidraDecompiler.cpp
 * in projcet https://github.com/radareorg/r2ghidra-dec.
 */

#include "R2RetDec.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

R2RetDec::R2RetDec(QObject *parent)
	: Decompiler("r2retdec", "RetDec", parent)
{
	task = nullptr;
}

void R2RetDec::decompileAt(RVA addr)
{
	if(task)
		return;

	AnnotatedCode code = {};

	task = new R2Task ("pdzj @ " + QString::number(addr));

	connect(task, &R2Task::finished, this, [this]() {
		AnnotatedCode code = {};
		QString s;

		QJsonObject json = task->getResultJson().object();
		delete task;
		task = nullptr;
		if(json.isEmpty())
		{
			code.code = tr("Failed to parse JSON from r2retdec");
			emit finished(code);
			return;
		}

		auto root = json;
		code.code = root["code"].toString();

		for(QJsonValueRef annotationValue : root["annotations"].toArray())
		{
			QJsonObject annotationObject = annotationValue.toObject();
			CodeAnnotation annotation = {};
			annotation.start = (size_t)annotationObject["start"].toVariant().toULongLong();
			annotation.end = (size_t)annotationObject["end"].toVariant().toULongLong();
			if(annotationObject["type"].toString() == "offset")
			{
				annotation.type = CodeAnnotation::Type::Offset;
				annotation.offset.offset = annotationObject["offset"].toVariant().toULongLong();
			}
			else
				continue;
			code.annotations.push_back(annotation);
		}

		for(QJsonValueRef error : json["errors"].toArray())
			code.code += "// " + error.toString() + "\n";

		emit finished(code);
	});
	task->startTask();

}

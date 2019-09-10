/*
 * libusb strerror code
 * Copyright © 2013 Hans de Goede <hdegoede@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <config.h>

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif

#include "libusbi.h"

#if defined(_MSC_VER)
#define strncasecmp _strnicmp
#endif

static size_t usbi_locale = 0;

static const char* usbi_locale_supported[] = { "en", "nl", "fr", "ru", "de", "hu" };
static const char* usbi_localized_errors[ARRAYSIZE(usbi_locale_supported)][LIBUSB_ERROR_COUNT] = {
	{ /* English (en) */
		"Success",
		"Input/Output Error",
		"Invalid parameter",
		"Access denied (insufficient permissions)",
		"No such device (it may have been disconnected)",
		"Entity not found",
		"Resource busy",
		"Operation timed out",
		"Overflow",
		"Pipe error",
		"System call interrupted (perhaps due to signal)",
		"Insufficient memory",
		"Operation not supported or unimplemented on this platform",
		"Other error",
	}, { /* Dutch (nl) */
		"Gelukt",
		"Invoer-/uitvoerfout",
		"Ongeldig argument",
		"Toegang geweigerd (onvoldoende toegangsrechten)",
		"Apparaat bestaat niet (verbinding met apparaat verbroken?)",
		"Niet gevonden",
		"Apparaat of hulpbron is bezig",
		"Bewerking verlopen",
		"Waarde is te groot",
		"Gebroken pijp",
		"Onderbroken systeemaanroep",
		"Onvoldoende geheugen beschikbaar",
		"Bewerking wordt niet ondersteund",
		"Andere fout",
	}, { /* French (fr) */
		"Succès",
		"Erreur d'entrée/sortie",
		"Paramètre invalide",
		"Accès refusé (permissions insuffisantes)",
		"Périphérique introuvable (peut-être déconnecté)",
		"Elément introuvable",
		"Resource déjà occupée",
		"Operation expirée",
		"Débordement",
		"Erreur de pipe",
		"Appel système abandonné (peut-être à cause d’un signal)",
		"Mémoire insuffisante",
		"Opération non supportée or non implémentée sur cette plateforme",
		"Autre erreur",
	}, { /* Russian (ru) */
		"Успех",
		"Ошибка ввода/вывода",
		"Неверный параметр",
		"Доступ запрещён (не хватает прав)",
		"Устройство отсутствует (возможно, оно было отсоединено)",
		"Элемент не найден",
		"Ресурс занят",
		"Истекло время ожидания операции",
		"Переполнение",
		"Ошибка канала",
		"Системный вызов прерван (возможно, сигналом)",
		"Память исчерпана",
		"Операция не поддерживается данной платформой",
		"Неизвестная ошибка"
	
	}, { /* German (de) */
		"Erfolgreich",
		"Eingabe-/Ausgabefehler",
		"Ungültiger Parameter",
		"Keine Berechtigung (Zugriffsrechte fehlen)",
		"Kein passendes Gerät gefunden (es könnte entfernt worden sein)",
		"Entität nicht gefunden",
		"Die Ressource ist belegt",
		"Die Wartezeit für die Operation ist abgelaufen",
		"Mehr Daten empfangen als erwartet",
		"Datenübergabe unterbrochen (broken pipe)",
		"Unterbrechung während des Betriebssystemaufrufs",
		"Nicht genügend Hauptspeicher verfügbar",
		"Die Operation wird nicht unterstützt oder ist auf dieser Platform nicht implementiert",
		"Allgemeiner Fehler",
	}, { /* Hungarian (hu) */
		"Sikeres",
		"Be-/kimeneti hiba",
		"Érvénytelen paraméter",
		"Hozzáférés megtagadva",
		"Az eszköz nem található (eltávolították?)",
		"Nem található",
		"Az erőforrás foglalt",
		"Időtúllépés",
		"Túlcsordulás",
		"Törött adatcsatorna",
		"Rendszerhívás megszakítva",
		"Nincs elég memória",
		"A művelet nem támogatott ezen a rendszeren",
		"Általános hiba",
	}
};


int API_EXPORTED libusb_setlocale(const char *locale)
{
	size_t i;

	if ( (locale == NULL) || (strlen(locale) < 2)
	  || ((strlen(locale) > 2) && (locale[2] != '-') && (locale[2] != '_') && (locale[2] != '.')) )
		return LIBUSB_ERROR_INVALID_PARAM;

	for (i=0; i<ARRAYSIZE(usbi_locale_supported); i++) {
		if (strncasecmp(usbi_locale_supported[i], locale, 2) == 0)
			break;
	}
	if (i >= ARRAYSIZE(usbi_locale_supported)) {
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_locale = i;

	return LIBUSB_SUCCESS;
}

DEFAULT_VISIBILITY const char* LIBUSB_CALL libusb_strerror(enum libusb_error errcode)
{
	int errcode_index = -errcode;

	if ((errcode_index < 0) || (errcode_index >= LIBUSB_ERROR_COUNT)) {
		/* "Other Error", which should always be our last message, is returned */
		errcode_index = LIBUSB_ERROR_COUNT - 1;
	}

	return usbi_localized_errors[usbi_locale][errcode_index];
}

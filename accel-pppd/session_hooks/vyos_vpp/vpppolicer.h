/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

int vpppolicer_install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst);
int vpppolicer_remove_limiter(struct ap_session *ses);

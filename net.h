/*
  Copyright (C) 2017 Christof Efkemann.
  This file is part of nlddcd.

  nlddcd is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  nlddcd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with nlddcd.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _NLDDCD_NET_H_
#define _NLDDCD_NET_H_

#include <stdbool.h>

#include "conf.h"

void perform_ddns_update(interface_status_t *if_stat);
void resolve_domain(interface_status_t *if_stat);
bool init_net(void);
void cleanup_net(void);

#endif

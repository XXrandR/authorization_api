# Registro: corrección de violaciones de SQL Lint (sqlfluff 4.4.0)

El job de CI **SQL Lint (migraciones)** fallaba con **66 violaciones** en los 9
scripts de Flyway (log de referencia: `2_SQL Lint (migraciones).txt`). Tras la
intervención, `sqlfluff lint src/main/resources/db/migration --dialect postgres`
termina con **0 violaciones**. No se desactivaron reglas ni se añadió
configuración de SQLFluff para ignorar hallazgos: las violaciones se corrigieron
en el código.

## Cambios aplicados

1. **Formato y capitalización (~48 violaciones)** aplicados con `sqlfluff fix`:
   indentación (`LT01`, `LT02`), líneas largas (`LT05`), salto de línea antes de
   `WHERE`/final de archivo (`LT09`, `LT12`, `LT14`), mayúsculas/minúsculas
   (`CP03`, `CP05`) y alias de tabla explícitos con `AS` / `INNER JOIN`
   (`AL01`, `AM05`).

2. **Columnas que usaban palabras reservadas de SQL (`RF04`)** renombradas en
   las migraciones, junto con sus `ON CONFLICT`, `CHECK`, índices y constraint
   única. Al estar entrecomilladas salta `RF06` ("comillas innecesarias"), por
   lo que el renombrado era la única corrección válida con las reglas por
   defecto:

   | Tabla | Columna anterior | Columna nueva |
   |---|---|---|
   | `auth.role` | `name` | `role_name` |
   | `auth.external_identity` | `provider` | `identity_provider` |
   | `auth.external_identity` | `name` | `display_name` |
   | `auth.external_identity` | `locale` | `locale_code` |
   | `auth.verification_token` | `type` | `token_type` |
   | `auth.audit_event` | `action` | `event_action` |

3. **Alias de columna repetidos (`AL08`)**: los `SELECT ... i.id, r.id` ahora
   usan alias distintos (`identity_id`, `role_id`).

4. **Literales JSON largos (`LT05`)**: los JSON de `client_settings` y
   `token_settings` en `V1_0_6` pasaron a formato multilínea, igual que ya hacía
   `V1_0_1`. Se comprobó con `::jsonb` que el valor es idéntico al original.

## Ajustes en la aplicación

- `Role` → `@Column(name = "role_name")` y `VerificationToken` →
  `@Column(name = "token_type")`. Los nombres de campo y los métodos derivados
  (`findByName`) no cambiaron.
- SQL nativo actualizado en `AdminQueryService`, `AuditService` e
  `InfrastructureOperationsService`.
- El contrato JSON del portal se mantuvo intacto usando aliases en las
  consultas: `role_name AS name` y `event_action AS action`.

## Verificación realizada

- `sqlfluff lint ... --dialect postgres`: 0 violaciones (antes 66).
- `./gradlew compileJava compileTestJava` y `./gradlew test`: correctos.
- Las 9 migraciones se ejecutaron en una base PostgreSQL limpia: todas aplican
  sin errores. Se comprobaron columnas, índices, `CHECK`, datos sembrados y que
  el trigger *append-only* de `auth.audit_event` sigue bloqueando `UPDATE` y
  `DELETE`.

## Notas operativas

- Editar migraciones ya aplicadas cambia su checksum de Flyway. Esto se hizo
  bajo el supuesto confirmado de que solo existen bases de desarrollo; en un
  entorno donde ya estén aplicadas habrá que limpiar/rebasar la base o usar una
  nueva.
- Quedó una base temporal llamada `oscar_lint_check` creada para la
  verificación; eliminarla cuando ya no se necesite.

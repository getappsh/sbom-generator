import { MigrationInterface, QueryRunner } from "typeorm";

export class AddArgsAndIsExeToDeliveryItem1769340297112 implements MigrationInterface {
    name = 'AddArgsAndIsExeToDeliveryItem1769340297112'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "delivery_item" ADD COLUMN IF NOT EXISTS "is_executable" boolean NOT NULL DEFAULT false`);
        await queryRunner.query(`ALTER TABLE "delivery_item" ADD COLUMN IF NOT EXISTS "arguments" text`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "delivery_item" DROP COLUMN IF EXISTS "arguments"`);
        await queryRunner.query(`ALTER TABLE "delivery_item" DROP COLUMN IF EXISTS "is_executable"`);
    }

}

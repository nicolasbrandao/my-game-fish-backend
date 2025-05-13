import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index({ unique: true })
  @Column()
  email: string;

  @Column({ nullable: true })
  displayName?: string;

  @Index({ unique: true, sparse: true })
  @Column({ nullable: true })
  googleId?: string;

  @Column({ type: 'text', nullable: true })
  googleAccessToken?: string;

  @Column({ type: 'text', nullable: true })
  googleRefreshToken?: string;

  @Column({ type: 'jsonb', nullable: true })
  googleProfileJson?: Record<string, any>;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
